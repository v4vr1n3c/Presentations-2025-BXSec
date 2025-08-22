### 1. Descoberta de Subdomínios

* **Persona:** Analista de Segurança Júnior
* **Tarefa:** Descobrir subdomínios válidos para um domínio alvo.
* **Etapas:**
    1.  Coleta de informações públicas usando ferramentas como **Amass** e **Subfinder**.
    2.  Verificação de registros DNS (A, AAAA, CNAME, MX) dos subdomínios encontrados.
    3.  Busca por subdomínios em sites de terceiros (certificados SSL, Shodan, etc.).
    4.  Organização e exportação dos resultados para análise.
* **Contexto:** Realizando a fase de reconhecimento em um teste de penetração externo.
* **Objetivo:** Obter uma lista abrangente de subdomínios para expandir a superfície de ataque.
* **Saída:** Uma lista de subdomínios ativos e seus endereços IP correspondentes em formato de texto (`.txt`) ou CSV (`.csv`).

### 2. Mapeamento de Portas e Serviços

* **Persona:** Engenheiro de Segurança Sênior
* **Tarefa:** Identificar portas abertas e serviços em execução em um host alvo.
* **Etapas:**
    1.  Execução de um escaneamento de portas abrangente com **Nmap**.
    2.  Detecção de versão e serviço (`-sV`).
    3.  Verificação de scripts de vulnerabilidade (`-sC`).
    4.  Análise dos resultados para identificar serviços mal configurados ou obsoletos.
* **Contexto:** Mapeamento inicial da rede após a descoberta de um host.
* **Objetivo:** Compreender a superfície de ataque do host e identificar potenciais vetores de entrada.
* **Saída:** Um relatório em XML ou HTML do Nmap, detalhando portas abertas, serviços, versões e vulnerabilidades conhecidas.

### 3. Enumeração de Diretórios Web

* **Persona:** Analista de Vulnerabilidades
* **Tarefa:** Encontrar diretórios e arquivos sensíveis em um servidor web.
* **Etapas:**
    1.  Utilização de ferramentas como **Gobuster** ou **Dirbuster** com dicionários de palavras (`wordlists`) otimizados.
    2.  Busca por arquivos de backup, `git` repositórios, arquivos de configuração (`.env`) e APIs não documentadas.
    3.  Filtragem de respostas 404 para evitar falsos positivos.
* **Contexto:** Exploração inicial de uma aplicação web.
* **Objetivo:** Descobrir informações valiosas que podem levar a vazamento de dados ou a uma execução de comando remoto.
* **Saída:** Uma lista de URLs válidas que correspondem a diretórios e arquivos descobertos.

### 4. Análise de Vulnerabilidades em Aplicações Web

* **Persona:** Pentester de Aplicações Web
* **Tarefa:** Identificar vulnerabilidades OWASP Top 10 em uma aplicação web.
* **Etapas:**
    1.  Escaneamento automatizado com **OWASP ZAP** ou **Nikto**.
    2.  Análise manual para confirmação de vulnerabilidades como Injeção SQL, Cross-Site Scripting (XSS), e Insecure Deserialization.
    3.  Geração de um relatório detalhado.
* **Contexto:** Teste de segurança de uma nova funcionalidade em uma aplicação web.
* **Objetivo:** Encontrar e documentar falhas de segurança na lógica da aplicação.
* **Saída:** Relatório em HTML ou PDF com a descrição de cada vulnerabilidade, impacto e passos para reprodução.

---

### 5. Análise de Credenciais Vazadas

* **Persona:** Especialista em Inteligência de Ameaças
* **Tarefa:** Verificar se credenciais de e-mail e senhas de colaboradores estão em bases de dados vazadas.
* **Etapas:**
    1.  Coleta de e-mails corporativos da empresa alvo através de ferramentas OSINT (como o **theHarvester**).
    2.  Consulta em bases de dados públicas como o **Have I Been Pwned** ou repositórios privados.
    3.  Avisos de segurança com informações de como proceder.
* **Contexto:** Fase de inteligência de ameaças e verificação de superfície de ataque humana.
* **Objetivo:** Identificar riscos de comprometimento de contas e auxiliar na mitigação do risco de ataque de força bruta ou engenharia social.
* **Saída:** Relatório com e-mails encontrados em vazamentos, as bases de dados e a data do comprometimento.

### 6. Enumeração de Recursos da AWS S3

* **Persona:** Pentester Cloud
* **Tarefa:** Encontrar e listar buckets S3 configurados de forma insegura.
* **Etapas:**
    1.  Utilização de ferramentas como **S3Scanner** ou **S3-Hunter**.
    2.  Busca por nomes de buckets comuns ou relacionados ao nome da empresa.
    3.  Verificação das permissões de acesso (público para leitura ou escrita).
* **Contexto:** Avaliação da segurança da infraestrutura em nuvem (Cloud Security Assessment).
* **Objetivo:** Identificar vazamento de dados sensíveis armazenados em buckets S3 acessíveis publicamente.
* **Saída:** Uma lista de buckets S3 encontrados, juntamente com suas permissões de acesso.

### 7. Reconhecimento de Redes Sociais

* **Persona:** Investigador de Cibersegurança
* **Tarefa:** Coletar informações de funcionários da empresa em redes sociais.
* **Etapas:**
    1.  Busca por nomes de funcionários no LinkedIn, Twitter, Facebook e outros.
    2.  Uso de ferramentas como **Maltego** para mapear conexões e relações entre funcionários.
    3.  Análise de fotos e posts para obter informações sobre a infraestrutura da empresa (badges, crachás, etc.).
* **Contexto:** Preparação para um ataque de engenharia social.
* **Objetivo:** Obter informações valiosas sobre a estrutura organizacional e hábitos dos funcionários para crafting de mensagens de phishing.
* **Saída:** Um mapa de conexões, nomes, cargos, e informações pessoais de alvos potenciais.

### 8. Análise de Vulnerabilidades em Contêineres Docker

* **Persona:** DevSecOps
* **Tarefa:** Analisar imagens Docker em busca de vulnerabilidades e pacotes desatualizados.
* **Etapas:**
    1.  Execução de uma ferramenta como **Clair** ou **Trivy** para escanear a imagem Docker.
    2.  Geração de um relatório de vulnerabilidades.
    3.  Análise dos resultados e recomendação de correções.
* **Contexto:** Integração de segurança no pipeline de CI/CD.
* **Objetivo:** Garantir que imagens de contêineres estejam livres de vulnerabilidades conhecidas antes de serem implantadas em produção.
* **Saída:** Relatório em formato JSON ou CSV com a lista de vulnerabilidades encontradas, suas gravidades (CVSS) e os pacotes afetados.

---

### 9. Descoberta de Arquivos Expostos em Repositórios Git

* **Persona:** Caçador de Bug Bounty
* **Tarefa:** Encontrar credenciais e chaves API expostas em repositórios Git públicos.
* **Etapas:**
    1.  Uso de ferramentas como **TruffleHog** ou **GitLeaks**.
    2.  Busca por `secrets` (`chaves`, `tokens`, `senhas`) em histórico de commits e repositórios.
    3.  Validação manual das credenciais encontradas.
* **Contexto:** Buscando recompensas por encontrar vulnerabilidades em programas de Bug Bounty.
* **Objetivo:** Encontrar credenciais que possam dar acesso a sistemas internos ou APIs.
* **Saída:** Uma lista de arquivos, hashes de commit e credenciais que foram expostas.

### 10. Enumeração de Usuários do Sistema

* **Persona:** Administrador de Sistemas
* **Tarefa:** Listar usuários válidos em um serviço de rede (como SSH ou FTP).
* **Etapas:**
    1.  Tentativa de autenticação com nomes de usuários comuns (root, admin, guest) em um serviço.
    2.  Utilização de ferramentas de brute-force de nome de usuário como **Hydra** em conjunto com uma wordlist de usernames.
* **Contexto:** Preparação para um ataque de força bruta de credenciais.
* **Objetivo:** Obter uma lista de nomes de usuários válidos para otimizar um ataque de força bruta de senha.
* **Saída:** Uma lista de nomes de usuários que foram considerados válidos pelo sistema.

### 11. Análise de Vulnerabilidades em Dispositivos IoT

* **Persona:** Pentester de Hardware
* **Tarefa:** Identificar vulnerabilidades em um dispositivo IoT conectado à rede.
* **Etapas:**
    1.  Escaneamento de portas para descobrir serviços abertos.
    2.  Busca por firmware desatualizado com vulnerabilidades conhecidas (`CVEs`).
    3.  Tentativa de autenticação com credenciais padrão ou fracas.
* **Contexto:** Teste de segurança de um dispositivo IoT antes da implantação em grande escala.
* **Objetivo:** Encontrar falhas de segurança que possam levar ao controle do dispositivo por invasores.
* **Saída:** Relatório com as vulnerabilidades encontradas, incluindo senhas padrão, firmware desatualizado e serviços inseguros.

### 12. Reconhecimento de APIs

* **Persona:** Pentester de Backend
* **Tarefa:** Mapear os endpoints de uma API e identificar sua estrutura.
* **Etapas:**
    1.  Captura e análise de tráfego com **Burp Suite Community Edition** ou **mitmproxy**.
    2.  Uso de **Postman** ou **curl** para testar os endpoints e entender a lógica da API.
    3.  Identificação de endpoints não documentados ou com falta de controle de acesso.
* **Contexto:** Avaliação de segurança de uma API RESTful.
* **Objetivo:** Compreender a superfície de ataque da API e identificar falhas de lógica ou autorização.
* **Saída:** Documentação detalhada dos endpoints, parâmetros, métodos HTTP e exemplos de requisições.

---

### 13. Análise de Arquivos de Configuração

* **Persona:** Auditor de Segurança
* **Tarefa:** Encontrar informações sensíveis em arquivos de configuração públicos (`.env`, `config.php`, etc.).
* **Etapas:**
    1.  Uso de motores de busca avançados (Google Dorks) para encontrar arquivos de configuração expostos.
    2.  Análise do conteúdo dos arquivos para credenciais, chaves de API, tokens e informações de conexão com banco de dados.
    3.  Validação das credenciais e comunicação ao cliente.
* **Contexto:** Fase de reconhecimento passivo.
* **Objetivo:** Obter acesso a sistemas internos através de credenciais expostas publicamente.
* **Saída:** Capturas de tela e trechos de código dos arquivos de configuração expostos.

### 14. Análise de Vulnerabilidades de Phishing

* **Persona:** Analista de Blue Team
* **Tarefa:** Avaliar a vulnerabilidade de um grupo de funcionários a ataques de phishing.
* **Etapas:**
    1.  Criação de um e-mail de phishing convincente com **Gophish**.
    2.  Envio da campanha de e-mail e monitoramento das interações (abertura, cliques, envio de dados).
    3.  Coleta de métricas e identificação de funcionários que caíram no teste.
* **Contexto:** Simulação de ataque controlado para conscientização e treinamento de segurança.
* **Objetivo:** Medir a conscientização de segurança da equipe e identificar a necessidade de treinamento.
* **Saída:** Relatório com a taxa de sucesso do phishing, a lista de usuários que clicaram nos links e recomendações para treinamento de conscientização.

### 15. Exploração de Vulnerabilidades de LFI/RFI

* **Persona:** Pentester Experiente
* **Tarefa:** Explotar uma vulnerabilidade de LFI (Local File Inclusion) ou RFI (Remote File Inclusion).
* **Etapas:**
    1.  Identificação de parâmetros vulneráveis na URL.
    2.  Uso de payloads para ler arquivos sensíveis do sistema (como `/etc/passwd`).
    3.  Tentativa de execução de comando remoto usando o RFI.
* **Contexto:** Exploração de vulnerabilidade de inclusão de arquivos em um servidor web.
* **Objetivo:** Obter acesso a arquivos de sistema sensíveis ou executar comandos remotos.
* **Saída:** Capturas de tela da prova de conceito (PoC) da vulnerabilidade, mostrando o conteúdo de arquivos lidos ou a execução de comandos.

---

### 16. Mapeamento de Credenciais em Rede Interna

* **Persona:** Pentester em Rede Interna
* **Tarefa:** Mapear credenciais de usuários e hashes de senhas em um ambiente interno.
* **Etapas:**
    1.  Utilização de ferramentas como **Responder.py** para envenenamento de ARP e captura de hashes NTLMv2.
    2.  Tentativa de cracking de hashes com **John the Ripper** ou **Hashcat**.
    3.  Uso de ferramentas como **Impacket** para **pass-the-hash** ou **pass-the-ticket**.
* **Contexto:** Exploração de uma vulnerabilidade de rede interna para escalar privilégios.
* **Objetivo:** Obter credenciais de contas privilegiadas para mover lateralmente na rede.
* **Saída:** Uma lista de hashes e senhas em texto claro que foram crackeados.

### 17. Análise de Fluxo de Dados em Aplicações Mobile

* **Persona:** Pentester Mobile
* **Tarefa:** Analisar o tráfego de rede de uma aplicação mobile em busca de dados sensíveis não criptografados.
* **Etapas:**
    1.  Configuração de um proxy como o **Burp Suite Community Edition** ou **mitmproxy** no dispositivo mobile.
    2.  Interação com o aplicativo, capturando e inspecionando o tráfego.
    3.  Busca por informações como credenciais, tokens, ou dados de pagamento em texto claro.
* **Contexto:** Auditoria de segurança de uma aplicação mobile.
* **Objetivo:** Identificar e documentar vazamentos de dados ou comunicação insegura entre o aplicativo e o servidor.
* **Saída:** Relatório com capturas de tráfego, evidenciando a transmissão de dados sensíveis sem criptografia.

### 18. Avaliação de Proteção de Brute-Force

* **Persona:** Analista de Segurança
* **Tarefa:** Testar a robustez dos mecanismos de proteção contra ataques de força bruta em um formulário de login.
* **Etapas:**
    1.  Uso de ferramentas como **Hydra** ou **Medusa** para um ataque de força bruta em um formulário de login.
    2.  Monitoramento das respostas do servidor para identificar bloqueios de IP, `CAPTCHAs` ou atrasos de tempo.
    3.  Análise da taxa de sucesso e do tempo necessário para bloquear um ataque.
* **Contexto:** Teste de segurança de um sistema de autenticação.
* **Objetivo:** Determinar a eficácia dos controles de segurança contra ataques de adivinhação de senhas.
* **Saída:** Relatório detalhado sobre o comportamento do sistema de login e as contramedidas implementadas, juntamente com a taxa de sucesso do ataque.

---

### 19. Análise de Vulnerabilidades em Software Obsoleto

* **Persona:** Auditor de Segurança
* **Tarefa:** Identificar versões de software vulneráveis e desatualizadas em um host.
* **Etapas:**
    1.  Uso de **Nmap** para detecção de versões de serviços.
    2.  Consulta a bancos de dados de vulnerabilidades (como **Exploit-DB** ou **Metasploit**) com as versões descobertas.
    3.  Tentativa de exploração manual de uma vulnerabilidade conhecida.
* **Contexto:** Avaliação inicial de um host em busca de pontos de entrada fáceis.
* **Objetivo:** Encontrar vulnerabilidades conhecidas em software que não foi atualizado.
* **Saída:** Lista de softwares desatualizados, suas versões e referências para as vulnerabilidades conhecidas (CVEs).

### 20. Engenharia Social via Voz (Vishing)

* **Persona:** Especialista em Engenharia Social
* **Tarefa:** Simular um ataque de engenharia social por telefone para obter informações confidenciais.
* **Etapas:**
    1.  Criação de um cenário convincente (por exemplo, "Suporte Técnico" ou "RH").
    2.  Utilização de ferramentas de voz (como **Twilio** com a API para simular números internos).
    3.  Gravação das chamadas e documentação das informações obtidas.
* **Contexto:** Teste de conscientização de segurança para a equipe, avaliando a capacidade de um funcionário de divulgar informações confidenciais.
* **Objetivo:** Avaliar a vulnerabilidade humana e a eficácia de treinamento de segurança.
* **Saída:** Relatório detalhado com a descrição da interação, informações obtidas e recomendações para treinamento.
