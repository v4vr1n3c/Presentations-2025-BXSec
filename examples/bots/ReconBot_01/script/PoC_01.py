import requests
import dns.resolver
import json
import time
import csv
from datetime import datetime
from bs4 import BeautifulSoup
import config

def verbose_print(*args):
    if config.VERBOSE:
        print(*args)

def consultar_dns(dominio):
    registros = {}
    tipos = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for t in tipos:
        try:
            answers = resolver.resolve(dominio, t)
            registros[t] = []
            for rdata in answers:
                if t == 'MX':
                    registros[t].append(str(rdata.exchange).rstrip('.'))
                elif t == "TXT":
                    txt_string = ''.join([part.decode('utf-8') if isinstance(part, bytes) else str(part) for part in rdata.strings])
                    registros[t].append(txt_string)
                else:
                    registros[t].append(str(rdata))
        except Exception as e:
            registros[t] = []
            verbose_print(f"[DNS] Sem resposta para {t}: {e}")
    return registros

def buscar_shodan_ips(ips):
    headers = {'Accept': 'application/json'}
    resultados = {}

    for ip in ips:
        verbose_print(f"[Shodan] Consultando {ip}")
        url = f"https://api.shodan.io/shodan/host/{ip}?key={config.SHODAN_API_KEY}"
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                resultados[ip] = {
                    'ip_str': data.get('ip_str', ''),
                    'org': data.get('org', ''),
                    'os': data.get('os', ''),
                    'ports': data.get('ports', []),
                    'banners': [s.get('data', '') for s in data.get('data', [])],
                    'vulns': data.get('vulns', {})
                }
            else:
                resultados[ip] = {'error': f"HTTP {resp.status_code}"}
                verbose_print(f"[Shodan] Erro HTTP {resp.status_code} para {ip}")
        except Exception as e:
            resultados[ip] = {'error': str(e)}
            verbose_print(f"[Shodan] Exceção para {ip}: {e}")

        time.sleep(1)  # rate limit

    return resultados

def consultar_crtsh(dominio):
    url = f"https://crt.sh/?q=%25.{dominio}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            certificados = []
            seen_ids = set()
            for cert in data:
                # Evitar duplicatas pelo cert id
                cid = cert.get("min_cert_id")
                if cid in seen_ids:
                    continue
                seen_ids.add(cid)
                certificados.append({
                    "issuer_ca_id": cert.get("issuer_ca_id"),
                    "issuer_name": cert.get("issuer_name"),
                    "common_name": cert.get("common_name"),
                    "name_value": cert.get("name_value"),
                    "min_cert_id": cert.get("min_cert_id"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                })
            return certificados
        else:
            verbose_print(f"[crt.sh] Status HTTP {resp.status_code}")
            return []
    except Exception as e:
        verbose_print(f"[crt.sh] Exceção: {e}")
        return []

def enumerar_subdominios_crtsh(dominio):
    certificados = consultar_crtsh(dominio)
    subs = set()
    for c in certificados:
        names = c.get("name_value", "")
        for name in names.split('\n'):
            n = name.strip().lower()
            if n.endswith(dominio):
                subs.add(n)
    return sorted(subs)

def enumerar_subdominios_dnsdumpster(dominio):
    url = "https://dnsdumpster.com/"
    session = requests.Session()

    try:
        r = session.get(url, timeout=10)
    except Exception as e:
        verbose_print(f"[dnsdumpster] Erro no GET: {e}")
        return []

    soup = BeautifulSoup(r.text, 'html.parser')
    token_input = soup.find("input", {"name": "csrfmiddlewaretoken"})

    if not token_input:
        verbose_print("[dnsdumpster] Token não encontrado na página inicial")
        return []

    csrf_token = token_input['value']

    headers = {
        "Referer": url,
        "User-Agent": "Mozilla/5.0 (compatible; ReconBot/1.0)",
    }

    data = {
        "csrfmiddlewaretoken": csrf_token,
        "targetip": dominio
    }

    try:
        response = session.post(url, headers=headers, data=data, timeout=20)
    except Exception as e:
        verbose_print(f"[dnsdumpster] Erro no POST: {e}")
        return []

    soup = BeautifulSoup(response.text, 'html.parser')

    subs = set()
    tables = soup.find_all("table", {"class": "table table-bordered"})

    for table in tables:
        if "Host Records" in table.text or "DNS Records" in table.text:
            trs = table.find_all("tr")
            for tr in trs[1:]:
                tds = tr.find_all("td")
                if len(tds) >= 1:
                    host = tds[0].text.strip().lower()
                    if host.endswith(dominio):
                        subs.add(host)

    return sorted(subs)

def geolocalizar_ip(ip):
    url = config.GEOIP_API_URL.format(ip=ip)
    headers = {}
    if config.GEOIP_API_TOKEN:
        headers['Authorization'] = f"Bearer {config.GEOIP_API_TOKEN}"

    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "ip": ip,
                "cidade": data.get("city", ""),
                "pais": data.get("country", ""),
                "asn": data.get("org", ""),
                "latitude_longitude": data.get("loc", "")
            }
        else:
            verbose_print(f"[GeoIP] HTTP {resp.status_code} para IP {ip}")
            return {"ip": ip, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        verbose_print(f"[GeoIP] Exceção para IP {ip}: {e}")
        return {"ip": ip, "error": str(e)}

def score_exposicao(shodan_info):
    """
    Score simples baseado em quantidade de portas abertas e os banners (exposição)
    """
    score = 0
    if "ports" in shodan_info:
        score += len(shodan_info["ports"]) * 10  # 10 pontos por porta aberta
    if "banners" in shodan_info:
        for banner in shodan_info["banners"]:
            # Aumenta o score se banner indicar software antigo ou vulnerabilidades conhecidas
            if any(x in banner.lower() for x in ['apache', 'nginx', 'iis', 'ssh', 'ftp']):
                score += 5
    return min(score, 100)  # máximo 100

def classificar_risco(score):
    if score >= 70:
        return "Alto"
    elif score >= 40:
        return "Médio"
    elif score > 0:
        return "Baixo"
    else:
        return "Desconhecido"

def coletar_vulnerabilidades_subdominios(subdominios, shodan_data):
    vulnerabilidades = {}

    for sub in subdominios:
        vulns_sub = set()
        try:
            answers = dns.resolver.resolve(sub, 'A', lifetime=5)
            for rdata in answers:
                ip = str(rdata)
                if ip in shodan_data:
                    shodan_vulns = shodan_data[ip].get('vulns', {})
                    if shodan_vulns:
                        vulns_sub.update(shodan_vulns.keys())
        except Exception:
            pass
        vulnerabilidades[sub] = sorted(vulns_sub)
    return vulnerabilidades

def exportar_csv(relatorio, nome_arquivo):
    try:
        with open(nome_arquivo, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['subdominio', 'vulnerabilidades', 'ip', 'geo_pais', 'geo_cidade', 'geo_asn', 'score_exposicao', 'risco']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for sub, vulns in relatorio['vulnerabilidades_subdominios'].items():
                ip = None
                geo = {}
                score = 0
                risco = "Desconhecido"
                try:
                    answers = dns.resolver.resolve(sub, 'A', lifetime=5)
                    for rdata in answers:
                        ip = str(rdata)
                        geo = relatorio['geolocalizacao_ips'].get(ip, {})
                        score = relatorio['score_exposicao'].get(ip, 0)
                        risco = relatorio['classificacao_risco'].get(ip, "Desconhecido")
                        break
                except Exception:
                    pass
                writer.writerow({
                    'subdominio': sub,
                    'vulnerabilidades': ', '.join(vulns),
                    'ip': ip or "",
                    'geo_pais': geo.get("pais", ""),
                    'geo_cidade': geo.get("cidade", ""),
                    'geo_asn': geo.get("asn", ""),
                    'score_exposicao': score,
                    'risco': risco
                })
        verbose_print(f"[CSV] Exportado arquivo {nome_arquivo}")
    except Exception as e:
        verbose_print(f"[CSV] Erro exportando CSV: {e}")

def gerar_resumo_markdown(relatorio, nome_arquivo_md):
    try:
        lines = [
            f"# Resumo Executivo Reconhecimento Passivo: {relatorio['dominio']}",
            "",
            f"Data: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Total de Subdomínios: {len(relatorio['subdominios'])}",
            f"Quantidade de IPs únicos: {len(relatorio['geolocalizacao_ips'])}",
            "",
            "## Subdomínios e Riscos",
            "| Subdomínio | Risco | Score Exposição | Vulnerabilidades |",
            "|------------|--------|----------------|------------------|"
        ]
        for sub in relatorio['subdominios']:
            vulns = relatorio['vulnerabilidades_subdominios'].get(sub, [])
            ip = None
            risco = "Desconhecido"
            score = 0
            try:
                answers = dns.resolver.resolve(sub, 'A', lifetime=5)
                for rdata in answers:
                    ip = str(rdata)
                    risco = relatorio['classificacao_risco'].get(ip, "Desconhecido")
                    score = relatorio['score_exposicao'].get(ip, 0)
                    break
            except Exception:
                pass
            vulns_str = ', '.join(vulns) if vulns else "Nenhuma"
            lines.append(f"| {sub} | {risco} | {score} | {vulns_str} |")

        with open(nome_arquivo_md, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        verbose_print(f"[MD] Resumo salvo em {nome_arquivo_md}")
    except Exception as e:
        verbose_print(f"[MD] Erro ao gerar resumo markdown: {e}")

def enviar_discord_webhook(webhook_url, mensagem):
    data = {"content": mensagem}
    try:
        resp = requests.post(webhook_url, json=data, timeout=5)
        return resp.status_code in [200, 204]
    except Exception as e:
        verbose_print(f"[Discord] Erro enviado webhook: {e}")
        return False

def main():
    dominio = input("Informe o domínio alvo (exemplo: exemplo.com): ").strip()

    verbose_print(f"=== INICIO DO RECON PASSIVO PARA {dominio} ===")

    dns_info = consultar_dns(dominio)
    ips = dns_info.get('A', []) + dns_info.get('AAAA', [])

    info_shodan = buscar_shodan_ips(ips) if config.SHODAN_API_KEY and config.SHODAN_API_KEY != "SUA_SHODAN_API_KEY_AQUI" else {}

    certificados = consultar_crtsh(dominio)
    subs_crtsh = enumerar_subdominios_crtsh(dominio)
    subs_dnsdumpster = enumerar_subdominios_dnsdumpster(dominio)
    subdominios = sorted(set(subs_crtsh + subs_dnsdumpster))

    vulnerabilidades = coletar_vulnerabilidades_subdominios(subdominios, info_shodan)

    # Geolocalização IPs únicos coletados via DNS para subdomínios e domínio root
    geolocalizacao_ips = {}
    todos_ips = set(ips)
    for sub in subdominios:
        try:
            answers = dns.resolver.resolve(sub, 'A', lifetime=5)
            for rdata in answers:
                todos_ips.add(str(rdata))
        except Exception:
            pass

    verbose_print(f"[GeoIP] Geolocalizando {len(todos_ips)} IPs únicos")
    for ip in todos_ips:
        geolocalizacao_ips[ip] = geolocalizar_ip(ip)
        time.sleep(0.5)  # evitar rate limit

    # Calcular score exposição e risco por IP
    score_exposicao_ips = {}
    classificacao_risco_ips = {}

    for ip in todos_ips:
        shodan_info = info_shodan.get(ip, {})
        score = score_exposicao(shodan_info)
        risco = classificar_risco(score)
        score_exposicao_ips[ip] = score
        classificacao_risco_ips[ip] = risco

    relatorio = {
        "dominio": dominio,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "dns": dns_info,
        "subdominios": subdominios,
        "certificados": certificados,
        "shodan": info_shodan,
        "vulnerabilidades_subdominios": vulnerabilidades,
        "geolocalizacao_ips": geolocalizacao_ips,
        "score_exposicao": score_exposicao_ips,
        "classificacao_risco": classificacao_risco_ips,
    }

    nome_arquivo = f"relatorio_recon_{dominio.replace('.', '_')}.json"
    with open(nome_arquivo, 'w', encoding='utf-8') as f:
        json.dump(relatorio, f, ensure_ascii=False, indent=4)

    if config.CSV_EXPORT:
        exportar_csv(relatorio, f"relatorio_recon_{dominio.replace('.', '_')}.csv")

    if config.MARKDOWN_SUMMARY:
        gerar_resumo_markdown(relatorio, f"resumo_recon_{dominio.replace('.', '_')}.md")

    # Construção da mensagem resumida para Discord
    lista_subs_formatada = '\n'.join(subdominios) if subdominios else "Nenhum subdomínio encontrado."
    texto_vulns = ""
    for idx, sd in enumerate(subdominios):
        vulns = vulnerabilidades.get(sd, [])
        if vulns:
            texto_vulns += f"\n{idx+1}. {sd} → Vulnerabilidades: {', '.join(vulns)}"

    if not texto_vulns:
        texto_vulns = "\nNenhuma vulnerabilidade encontrada nos subdomínios."

    mensagem = (
        f"Reconhecimento passivo concluído para: **{dominio}**\n"
        f"Total de subdomínios encontrados: {len(subdominios)}\n"
        f"Subdomínios:\n{lista_subs_formatada}\n\n"
        f"IPs obtidos via DNS (incluindo subdomínios): {len(todos_ips)}\n"
        f"Certificados encontrados (crt.sh): {len(certificados)}\n"
        f"Registros DNS:\n"
        f" - A: {len(dns_info.get('A', []))}\n"
        f" - AAAA: {len(dns_info.get('AAAA', []))}\n"
        f" - MX: {len(dns_info.get('MX', []))}\n"
        f" - NS: {len(dns_info.get('NS', []))}\n"
        f" - TXT: {len(dns_info.get('TXT', []))}\n"
        f"Shodan: {'Ativado' if info_shodan else 'Desativado ou sem dados'}\n"
        f"Vulnerabilidades encontradas por subdomínio:{texto_vulns}\n\n"
        f"Para detalhes completos veja o arquivo: {nome_arquivo}"
    )

    if config.DISCORD_WEBHOOK_URL and config.DISCORD_WEBHOOK_URL != "SEU_WEBHOOK_DISCORD_AQUI":
        enviado = enviar_discord_webhook(config.DISCORD_WEBHOOK_URL, mensagem)
        verbose_print(f"[Discord] Notificação enviada: {enviado}")
    else:
        verbose_print("[Discord] Webhook não configurado, notificação não enviada.")

    verbose_print("=== FIM DO RECON PASSIVO ===")

if __name__ == "__main__":
    main()
