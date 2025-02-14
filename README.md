# La Mafia - Ultimate Hacking Framework 🔥

**La Mafia** é uma ferramenta poderosa de pentesting e hacking, projetada para realizar uma ampla gama de testes de segurança em alvos. Com este framework, você pode realizar escaneamentos, brute-forcing, simulações de ataques DDoS, análise de cabeçalhos HTTP, escaneamentos com OpenVAS, verificações de senhas vazadas e muito mais. A ferramenta oferece tanto uma interface gráfica simples (GUI) quanto uma interface de linha de comando (CLI) para facilitar o uso em diferentes ambientes.

## Funcionalidades

- **Reconhecimento (Recon)**: Escaneamento de DNS, portas, CVEs, informações WHOIS, SSL/TLS e mais.
- **Força Bruta (BruteForce)**: Realiza ataques de força bruta em serviços como RDP e HTTP.
- **Simulação de DDoS (DDoS)**: Simula ataques DDoS usando `hping3`.
- **Cabeçalhos HTTP (HTTP)**: Análise de cabeçalhos HTTP para vulnerabilidades.
- **OpenVAS**: Realiza escaneamentos de vulnerabilidades com OpenVAS.
- **Pwned Passwords**: Verifica se a senha está vazada em bases de dados de vazamento.
- **Relatório**: Gera relatórios detalhados sobre os escaneamentos realizados.
- **Autodestruição (Self Destruct)**: Destrói dados e o próprio script de forma segura.

## Pré-requisitos

Antes de rodar o framework, você deve garantir que o seu sistema tenha as dependências necessárias:

- `subfinder`
- `amass`
- `nuclei`
- `sqlmap`
- `hydra`
- `tor`
- `assetfinder`
- `setoolkit`
- `dig`
- `dnsrecon`
- `nmap`
- `searchsploit`
- `whois`
- `openssl`
- `testssl.sh`
- `nikto`
- `hping3`
- `curl`
- `openvas-cli`

Além disso, se você preferir usar a interface gráfica (GUI), o `Zenity` deve estar instalado. Caso não tenha, você pode instalá-lo com o comando:

```bash
sudo apt install zenity
