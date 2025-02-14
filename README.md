La Mafia - Ultimate Hacking Framework 🔥
La Mafia é uma ferramenta poderosa de pentesting e hacking, projetada para realizar uma ampla gama de testes de segurança em alvos. Com este framework, você pode realizar escaneamentos, brute-forcing, simulações de ataques DDoS, análise de cabeçalhos HTTP, escaneamentos com OpenVAS, verificações de senhas vazadas e muito mais. A ferramenta oferece tanto uma interface gráfica simples (GUI) quanto uma interface de linha de comando (CLI) para facilitar o uso em diferentes ambientes.

Funcionalidades
Reconhecimento (Recon): Escaneamento de DNS, portas, CVEs, informações WHOIS, SSL/TLS e mais.
Força Bruta (BruteForce): Realiza ataques de força bruta em serviços como RDP e HTTP.
Simulação de DDoS (DDoS): Simula ataques DDoS usando hping3.
Cabeçalhos HTTP (HTTP): Análise de cabeçalhos HTTP para vulnerabilidades.
OpenVAS: Realiza escaneamentos de vulnerabilidades com OpenVAS.
Pwned Passwords: Verifica se a senha está vazada em bases de dados de vazamento.
Relatório: Gera relatórios detalhados sobre os escaneamentos realizados.
Autodestruição (Self Destruct): Destrói dados e o próprio script de forma segura.
Pré-requisitos
Antes de rodar o framework, você deve garantir que o seu sistema tenha as dependências necessárias:

subfinder
amass
nuclei
sqlmap
hydra
tor
assetfinder
setoolkit
dig
dnsrecon
nmap
searchsploit
whois
openssl
testssl.sh
nikto
hping3
curl
openvas-cli
Além disso, se você preferir usar a interface gráfica (GUI), o Zenity deve estar instalado. Caso não tenha, você pode instalá-lo com o comando:

bash
Copiar
Editar
sudo apt install zenity
Instalação
Clone o repositório:
bash
Copiar
Editar
git clone https://github.com/seu-usuario/la-mafia.git
cd la-mafia
Torne o script executável:
bash
Copiar
Editar
chmod +x la_mafia.sh
Execute o script:
Para usar a interface de linha de comando:
bash
Copiar
Editar
./la_mafia.sh
Para usar a interface gráfica (GUI):
bash
Copiar
Editar
./la_mafia.sh
Como Usar
Ao rodar o script, você será apresentado a opções de modo que permitem selecionar diferentes testes de segurança:

Recon: Realiza escaneamentos de DNS, portas, CVEs, etc.
BruteForce: Realiza ataques de força bruta.
DDoS: Simula um ataque DDoS.
HTTP: Analisa os cabeçalhos HTTP.
OpenVAS: Realiza um escaneamento com OpenVAS.
Pwned: Verifica se a senha está vazada.
Relatório: Gera um relatório completo dos escaneamentos.
Self Destruct: Destrói dados e o próprio script.
Exemplo de Uso no Terminal
bash
Copiar
Editar
./la_mafia.sh recon www.exemplo.com
Isso executará o modo "Recon" no alvo www.exemplo.com.

Exemplo de Uso na Interface Gráfica
Ao rodar o script com Zenity, você será guiado por uma interface gráfica para selecionar os modos e digitar o alvo.

Contribuindo
Se você deseja contribuir para o projeto, fique à vontade para abrir issues, enviar pull requests e sugerir melhorias. Para começar:

Fork o repositório.
Crie uma nova branch (git checkout -b feature/nova-funcionalidade).
Faça suas alterações e commite-as (git commit -m 'Adicionando nova funcionalidade').
Envie para o repositório remoto (git push origin feature/nova-funcionalidade).
Abra uma pull request.
