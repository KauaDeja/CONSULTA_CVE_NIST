import nvdlib 

ativos = {
    "Red Hat Enterprise Linux 9": "cpe:2.3:o:redhat:enterprise_linux:9",
    "Oracle Database 19c": "cpe:2.3:a:oracle:database_server:19c",
    "Juniper MX Series": "cpe:2.3:h:juniper:mx_series",
    "Ubuntu 22.04": "cpe:2.3:o:canonical:ubuntu_linux:22.04",
    "Mozilla Firefox": "cpe:2.3:a:mozilla:firefox"
}

for ativo in ativos: 
    print(f"\n=== CVEs para {ativo} ===") 

    results = nvdlib.searchCVE( 
        keywordSearch=ativo, 
        limit=5, 
        key="3dd2dbf2-fdbc-45bf-9e2c-4609e3df5023" ) 

    for cve in results: 
        print(cve.id, cve.score)