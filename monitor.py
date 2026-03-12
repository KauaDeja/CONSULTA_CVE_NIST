import os
import requests
import pandas as pd
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone
from email.header import Header # Adicione isso lá nos imports no topo do arquivo se não tiver

# Variáveis de Ambiente (Configuradas no GitHub Secrets)
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
CABECALHOS_REQUISICAO = {'User-Agent': 'Monitor-Vulnerabilidades/1.0'}
if CHAVE_API_NVD:
    CABECALHOS_REQUISICAO['apiKey'] = CHAVE_API_NVD

def registrar_log(mensagem):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {mensagem}")

def ler_cves_conhecidos():
    if os.path.exists(ARQUIVO_HISTORICO):
        with open(ARQUIVO_HISTORICO, "r") as arquivo:
            return set(arquivo.read().splitlines())
    return set()

def registrar_novo_cve(id_cve):
    with open(ARQUIVO_HISTORICO, "a") as arquivo:
        arquivo.write(id_cve + "\n")

def enviar_email_resumo(novos_dados):
    if not EMAIL_REMETENTE or not SENHA_REMETENTE:
        registrar_log("Credenciais de e-mail não configuradas. Pulando envio de alerta.")
        return

    assunto = f"[Monitor CVE] {len(novos_dados)} novas vulnerabilidades detectadas!"
    
    corpo = "Relatório Semanal de Vulnerabilidades:\n\n"
    for item in novos_dados:
        corpo += f" {item['Sistema Afetado']} | {item['ID CVE']} | CVSS: {item['Score CVSS']}\n"
        # Limpa o caracter fantasma \xa0 na hora de montar o e-mail
        desc_limpa = item['Descrição Técnica'].replace('\xa0', ' ')
        corpo += f"Descrição: {desc_limpa}\n"
        corpo += "-" * 50 + "\n"

    msg = MIMEMultipart()
    msg['From'] = EMAIL_REMETENTE
    msg['To'] = EMAIL_DESTINATARIO
    # Força o cabeçalho a aceitar acentos sem quebrar
    msg['Subject'] = Header(assunto, 'utf-8')
    corpo = corpo.encode('utf-8', 'ignore').decode('utf-8')
    msg.attach(MIMEText(corpo, 'plain', 'utf-8'))

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL_REMETENTE, SENHA_REMETENTE)
            server.send_message(msg)
        registrar_log(f"E-mail de resumo enviado com sucesso para {EMAIL_DESTINATARIO}!")
    except Exception as erro:
        registrar_log(f"Erro ao enviar e-mail: {erro}")

def executar_varredura():
    cves_processados = ler_cves_conhecidos()
    novos_dados_excel = []
    
    data_atual = datetime.now(timezone.utc)
    
    if not cves_processados:
        registrar_log("Nenhum histórico encontrado. Iniciando CARGA INICIAL desde 01/07/2025...")
        data_inicio_geral = datetime(2025, 7, 1, tzinfo=timezone.utc)
    else:
        # Como o bot vai rodar a cada 7 dias, ele busca exatamente os últimos 7 dias
        registrar_log("Histórico encontrado. Buscando novidades da última semana...")
        data_inicio_geral = data_atual - timedelta(days=7)

    total_novas_falhas = 0

    for nome_sistema, dados_alvo in ALVOS_MONITORAMENTO.items():
        termo_busca = dados_alvo["busca"]
        cpe_sistema = dados_alvo["cpe"]
        
        registrar_log(f"\nConsultando: {nome_sistema} (Buscando por: '{termo_busca}')")
        data_atual_inicio = data_inicio_geral
        
        while data_atual_inicio < data_atual:
            data_atual_fim = data_atual_inicio + timedelta(days=90)
            if data_atual_fim > data_atual:
                data_atual_fim = data_atual
                
            str_data_inicio = data_atual_inicio.strftime('%Y-%m-%dT%H:%M:%S.000') + '+00:00'
            str_data_fim = data_atual_fim.strftime('%Y-%m-%dT%H:%M:%S.000') + '+00:00'

            parametros_busca = {
                'keywordSearch': termo_busca,
                'pubStartDate': str_data_inicio,
                'pubEndDate': str_data_fim
            }

            try:
                resposta = requests.get(URL_API_NIST, headers=CABECALHOS_REQUISICAO, params=parametros_busca, timeout=30)
                if resposta.status_code == 200:
                    lista_vulnerabilidades = resposta.json().get('vulnerabilities', [])
                    
                    for item in lista_vulnerabilidades:
                        dados_cve = item.get('cve', {})
                        id_cve = dados_cve.get('id')
                        
                        if id_cve not in cves_processados:
                            data_publicacao = dados_cve.get('published', 'Data N/A')
                            # Como deve ficar agora (substitua por estas duas linhas):
                            descricao_tecnica_crua = next((d.get('value') for d in dados_cve.get('descriptions', []) if d.get('lang') == 'en'), "Sem descrição")
                            descricao_tecnica = descricao_tecnica_crua.replace('\xa0', ' ')
                            
                            pontuacao_cvss = 'N/A'
                            metricas = dados_cve.get('metrics', {})
                            if 'cvssMetricV31' in metricas:
                                pontuacao_cvss = metricas['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 'N/A')
                            elif 'cvssMetricV30' in metricas:
                                pontuacao_cvss = metricas['cvssMetricV30'][0].get('cvssData', {}).get('baseScore', 'N/A')

                            registrar_novo_cve(id_cve)
                            cves_processados.add(id_cve)
                            total_novas_falhas += 1

                            novos_dados_excel.append({
                                "Sistema Afetado": nome_sistema,
                                "CPE Base": cpe_sistema,
                                "ID CVE": id_cve,
                                "Data Publicação": data_publicacao[:10],
                                "Score CVSS": pontuacao_cvss,
                                "Descrição Técnica": descricao_tecnica
                            })
                else:
                    registrar_log(f"  -> Erro na API do NIST (Código {resposta.status_code})")
            except Exception as erro_conexao:
                registrar_log(f"  -> Falha de comunicação: {erro_conexao}")
            
            data_atual_inicio = data_atual_fim
            time.sleep(6)

    # Processamento final
    if total_novas_falhas > 0:
        # Envia o e-mail com as novidades da semana
        enviar_email_resumo(novos_dados_excel)
        
        # Salva no Excel
        df_dados_recentes = pd.DataFrame(novos_dados_excel)
        if os.path.exists(ARQUIVO_PLANILHA):
            df_base_antiga = pd.read_excel(ARQUIVO_PLANILHA)
            df_consolidado = pd.concat([df_base_antiga, df_dados_recentes]).drop_duplicates(subset=['ID CVE', 'Sistema Afetado'])
        else:
            df_consolidado = df_dados_recentes
            
        df_consolidado.to_excel(ARQUIVO_PLANILHA, index=False)
        registrar_log(f"\nOperação concluída. A planilha foi atualizada com {total_novas_falhas} novos CVEs.")
    else:
        registrar_log("\nNenhuma nova vulnerabilidade encontrada neste ciclo.")

if __name__ == "__main__":
    executar_varredura()
