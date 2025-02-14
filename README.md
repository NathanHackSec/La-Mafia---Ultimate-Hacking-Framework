# La Mafia - Ultimate Hacking Framework 🔥

**La Mafia** é uma ferramenta poderosa de pentesting e hacking, projetada para realizar uma ampla gama de testes de segurança em alvos. Com este framework, você pode realizar escaneamentos, brute-forcing, simulações de ataques DDoS, análise de cabeçalhos HTTP, escaneamentos com OpenVAS, verificações de senhas vazadas e muito mais. A ferramenta oferece tanto uma interface gráfica simples (GUI) quanto uma interface de linha de comando (CLI) para facilitar o uso em diferentes ambientes.

## 🚀 Funcionalidades  

- 🔍 **Reconhecimento (Recon):** Escaneamento de DNS, portas, CVEs, informações WHOIS, SSL/TLS e mais.
- 🔑 **Força Bruta (BruteForce):** Realiza ataques de força bruta em serviços como RDP e HTTP.
- 💥 **Simulação de DDoS (DDoS):** Simula ataques DDoS usando hping3.
- 🌍 **Cabeçalhos HTTP (HTTP):** Análise de cabeçalhos HTTP para vulnerabilidades.
- 🛡 **OpenVAS:** Escaneamento de vulnerabilidades com OpenVAS.
- 🔓 **Pwned Passwords:** Verifica se a senha está vazada em bases de dados de vazamento.
- 📊 **Relatório:** Gera relatórios detalhados sobre os escaneamentos realizados.
- 💣 **Autodestruição (Self Destruct):** Remove todos os dados e apaga o próprio script.

---

## 📌 Pré-requisitos, Instalação e Uso  

```bash
# Instalar pacotes necessários para o funcionamento do script:
sudo apt install subfinder amass nuclei sqlmap hydra tor assetfinder \
setoolkit dig dnsrecon nmap searchsploit whois openssl testssl.sh \
nikto hping3 curl openvas-cli

# Se desejar usar a interface gráfica (GUI), instale o Zenity:
sudo apt install zenity

# Clone o repositório para o seu sistema local:
git clone https://github.com/seu-usuario/la-mafia.git
cd la-mafia

# Torne o script executável:
chmod +x la_mafia.sh

# Execute o script via CLI:
./la_mafia.sh

# Execute o script via GUI:
./la_mafia.sh --gui

# Exemplos de uso:
# Para rodar o modo "Recon" no alvo www.exemplo.com:
./la_mafia.sh recon www.exemplo.com

# Contribuindo para o projeto:
git checkout -b feature/nova-funcionalidade
git commit -m "Adicionando nova funcionalidade"
git push origin feature/nova-funcionalidade
# Abra uma pull request no GitHub!
