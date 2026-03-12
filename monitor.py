import os
import requests
import pandas as pd
import time
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone

# Variáveis de Ambiente
CHAVE_API_NVD = os.environ.get("NVD_API_KEY")
EMAIL_REMETENTE = os.environ.get("EMAIL_USER")
SENHA_REMETENTE = os.environ.get("EMAIL_PASS")
EMAIL_DESTINATARIO = "kauakarate@gmail.com"

ALVOS_MONITORAMENTO = {
    "Red Hat Enterprise Linux 9": {"busca": "Red Hat Enterprise Linux 9", "cpe": "cpe:2.3:o:redhat:enterprise_linux:9"},
    "Oracle Database 19c": {"busca": "Oracle Database 19c", "cpe": "cpe:2.3:a:oracle:database_server:19c"},
    "Juniper MX Series": {"busca": "Juniper MX", "cpe": "cpe:2.3:h:juniper:mx_series"},
    "Ubuntu 22.04": {"busca": "Ubuntu 22.04", "cpe": "cpe:2.3:o:canonical:ubuntu_linux:22.04"},
    "Mozilla Firefox": {"busca": "Firefox", "cpe": "cpe:2.3:a:mozilla:firefox"}
}

ARQUIVO_HISTORICO = "cve_tracker.log"
ARQUIVO_PLANILHA = "relatorio_cves_recentes.xlsx"
URL_API_NIST = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def registrar_log(mensagem):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {mensagem}")

def ler_cves_conhecidos():
    if os.path.exists(ARQUIVO_HISTORICO):
        with open(ARQUIVO_HISTORICO, "r") as f:
            return set(f.read().splitlines())
    return set()

def registrar_novo_cve(id_cve):
    with open(ARQUIVO_HISTORICO, "a") as f:
        f.write(id_cve + "\n")

def enviar_email_resumo(novos_dados):
    if not EMAIL_REMETENTE or not SENHA_REMETENTE:
        registrar_log("Credenciais de e-mail não configuradas.")
        return

    assunto = f"Alerta de Segurança: {len(novos_dados)} nova(s) vulnerabilidade(s) detectada(s)"
    
    # Construindo o corpo do e-mail com os dados reais
    linhas_corpo = ["Olá,\n", "O monitoramento detectou os seguintes CVEs recentes:\n"]
    
    for item in novos_dados:
        linhas_corpo.append(f"🔴 Sistema Afetado: {item['Sistema Afetado']}")
        linhas_corpo.append(f"   ID CVE: {item['ID CVE']}")
        linhas_corpo.append(f"   Descrição: {item['Descrição Técnica']}")
        linhas_corpo.append("-" * 50) # Linha separadora entre os CVEs

    corpo_email = "\n".join(linhas_corpo)

    msg = EmailMessage()
    msg.set_content(corpo_email)
    msg['Subject'] = assunto
    msg['From'] = EMAIL_REMETENTE
    msg['To'] = EMAIL_DESTINATARIO

    try:
        # Trava de segurança: remove espaços acidentais da senha vinda do .env
        senha_limpa = SENHA_REMETENTE.replace(" ", "").replace("\xa0", "").strip()
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_REMETENTE, senha_limpa)
            server.send_message(msg)
        registrar_log(f"E-mail com relatório enviado com sucesso para {EMAIL_DESTINATARIO}")
    except Exception as erro:
        registrar_log(f"Erro ao enviar e-mail: {erro}")

def executar_varredura():
    conhecidos = ler_cves_conhecidos()
    novos_dados = []
    data_atual = datetime.now(timezone.utc)
    
    # Janela de 15 dias para o teste
    data_inicio = data_atual - timedelta(days=70)
    str_ini = data_inicio.strftime('%Y-%m-%dT%H:%M:%S.000') + '+00:00'
    str_fim = data_atual.strftime('%Y-%m-%dT%H:%M:%S.000') + '+00:00'
    
    headers = {'User-Agent': 'Monitor/1.0'}
    if CHAVE_API_NVD: headers['apiKey'] = CHAVE_API_NVD

    for nome, info in ALVOS_MONITORAMENTO.items():
        registrar_log(f"Verificando {nome}...")
        params = {'keywordSearch': info['busca'], 'pubStartDate': str_ini, 'pubEndDate': str_fim}
        
        try:
            r = requests.get(URL_API_NIST, headers=headers, params=params, timeout=30)
            if r.status_code == 200:
                vulns = r.json().get('vulnerabilities', [])
                for v in vulns:
                    cve_id = v.get('cve', {}).get('id')
                    if cve_id not in conhecidos:
                        desc = next((d.get('value') for d in v.get('cve', {}).get('descriptions', []) if d.get('lang') == 'en'), "N/A")
                        
                        registrar_novo_cve(cve_id)
                        conhecidos.add(cve_id)
                        novos_dados.append({
                            "Sistema Afetado": nome,
                            "ID CVE": cve_id,
                            "Score CVSS": "N/A",
                            "Descrição Técnica": desc
                        })
            time.sleep(6) # Respeitando o rate limit da NVD
        except Exception as e:
            registrar_log(f"Erro ao consultar NVD: {e}")

if novos_dados:
        enviar_email_resumo(novos_dados)
        df = pd.DataFrame(novos_dados)
        
        # Verifica se o arquivo existe e tem tamanho maior que 0 bytes
        if os.path.exists(ARQUIVO_PLANILHA) and os.path.getsize(ARQUIVO_PLANILHA) > 0:
            try:
                # Forçamos a engine openpyxl para evitar ambiguidades
                df_existente = pd.read_excel(ARQUIVO_PLANILHA, engine='openpyxl')
                df = pd.concat([df_existente, df]).drop_duplicates(subset=['ID CVE'])
            except Exception as e:
                registrar_log(f"Aviso: Arquivo Excel corrompido ou ilegível ({e}). Uma nova planilha será criada.")
        
        # Salva o resultado final forçando a engine correta
        df.to_excel(ARQUIVO_PLANILHA, index=False, engine='openpyxl')
        registrar_log(f"Planilha {ARQUIVO_PLANILHA} atualizada.")
    else:
        registrar_log("Nenhuma vulnerabilidade nova encontrada nesta varredura.")

if __name__ == "__main__":
    executar_varredura()
