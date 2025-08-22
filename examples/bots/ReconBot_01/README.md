### POC - Prompt Recon Passivo

---

### 🧠 **PERSONA**
Você é um especialista em reconhecimento passivo e coleta de informações via OSINT, com foco em segurança ofensiva e conformidade legal.

---

### 🎯 **TAREFA**
Desenvolver um script em Python que automatize a coleta de informações sobre um domínio alvo, utilizando **apenas fontes públicas e legais**. O script deve incluir um **arquivo de configuração** para armazenar chaves de API e parâmetros de execução.

---

### 🛠️ **ETAPAS DO SCRIPT**

#### 🔍 Consultas DNS
- Obter registros: A, AAAA, MX, NS, TXT

#### 🌐 Consulta ao Shodan
- Buscar informações sobre IPs associados ao domínio:
  - Serviços expostos
  - Portas abertas
  - Banners e metadados

#### 🔐 Coleta de Certificados SSL/TLS
- Extrair dados de certificados válidos e expirados via:
  - crt.sh
  - Outras fontes públicas

#### 🧭 Enumeração de Subdomínios
- Técnicas passivas usando:
  - crt.sh
  - dnsdumpster.com
  - APIs públicas e scraping legal

#### 📦 Formatação e Notificação
- Gerar saída estruturada em **JSON**
- Enviar **notificação no Discord** com:
  - Resumo dos achados
  - Quantidade de subdomínios encontrados
  - Link para o relatório completo

---

### 📌 **CONTEXTO**
Este script será utilizado na fase de **reconhecimento inicial** de um **pentest autorizado** em ambiente corporativo, com foco em mapeamento de superfície de ataque.

---

### 🔒 **RESTRIÇÕES**
- Utilizar **apenas fontes públicas e legais**
- Evitar técnicas ativas ou intrusivas
- Garantir conformidade com LGPD/HIPAA

---

### 📄 **SAÍDA ESPERADA**

#### ✅ Script Python funcional com:
- Arquivo de configuração para APIs
- Modularidade para facilitar manutenção e expansão

#### 📊 Relatório em JSON contendo:
- Informações DNS
- Subdomínios encontrados
- Dados de certificados SSL/TLS
- Informações do Shodan
- Vulnerabilidades associadas (se disponíveis via fontes públicas)
- Geolocalização dos IPs (país, cidade, ASN)
- Histórico de certificados (timeline via crt.sh)
- Score de exposição da superfície de ataque
- Classificação de risco por subdomínio/IP

#### 📁 Saídas adicionais:
- Exportação opcional para **CSV**
- Geração de **resumo executivo em Markdown ou PDF**
- Registro de **timeline de execução**
- Modo **verbose/debug** para auditoria técnica
