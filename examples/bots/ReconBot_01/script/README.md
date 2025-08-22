
# Reconhecimento Passivo com OSINT

Este projeto tem como objetivo automatizar a coleta de informações sobre um domínio alvo utilizando técnicas de reconhecimento passivo e fontes públicas.

## 🚀 Instalação

Instale as dependências necessárias com o seguinte comando:

```bash
pip install requests dnspython beautifulsoup4
```

## ⚙️ Configuração

Crie e configure o arquivo `config.py` com suas chaves de API e parâmetros personalizados. Exemplo:

```python
SHODAN_API_KEY = "sua_chave_aqui"
DISCORD_WEBHOOK_URL = "url_do_webhook"
```

## 🧪 Uso

Execute o script principal informando o domínio alvo:

```bash
python main.py --domain exemplo.com
```

O script irá gerar um relatório em JSON com os dados coletados e enviar uma notificação no Discord.

## 📄 Saída

- Relatório em JSON estruturado
- Notificação no Discord com resumo dos achados

---

**Importante:** Este script deve ser utilizado apenas em atividades de pentest autorizadas e em conformidade com a legislação vigente.
