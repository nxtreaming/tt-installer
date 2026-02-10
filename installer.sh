#!/bin/bash

set -e

# Configuration
INSTALL_DIR="/opt/trusttunnel"
CONFIG_DIR="${INSTALL_DIR}"
SERVICE_NAME="trusttunnel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
MARKER_FILE="${INSTALL_DIR}/.trusttunnel_configured"
INSTALLER_URL="https://raw.githubusercontent.com/deathline94/tt-installer/main/installer.sh"
MANAGER_SCRIPT="/root/tt-installer.sh"
MODE_MARKER="/etc/trusttunnel-installer-mode"

CLIENT_INSTALL_DIR="/opt/trusttunnel_client"
CLIENT_SERVICE_NAME="trusttunnel-client"
CLIENT_SERVICE_FILE="/etc/systemd/system/${CLIENT_SERVICE_NAME}.service"
CLIENT_CONFIG_FILE="${CLIENT_INSTALL_DIR}/trusttunnel_client.toml"
CLIENT_MARKER_FILE="${CLIENT_INSTALL_DIR}/.trusttunnel_client_configured"
CLIENT_INSTALL_URL="https://raw.githubusercontent.com/TrustTunnel/TrustTunnelClient/refs/heads/master/scripts/install.sh"

BUNDLE_PREFIX="TTB1"
BUNDLE_FILE="/root/trusttunnel-mainland.bundle"

FOUND_CERT_DOMAINS=()
FOUND_CERT_PATHS=()
FOUND_KEY_PATHS=()
FOUND_CERT_SOURCES=()
FOUND_CERT_PAIR_KEYS=()

unexpected_error_handler() {
    local exit_code="$1"
    local line_no="$2"
    echo ""
    echo "Error: Installer aborted at line ${line_no} (exit code: ${exit_code})"
}

trap 'unexpected_error_handler $? $LINENO' ERR

# Function to print characters with delay
print_with_delay() {
    text="$1"
    delay="$2"
    for ((i = 0; i < ${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep "$delay"
    done
    echo
}

# ============================================================================
# Utility Functions
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root (use sudo)"
        exit 1
    fi
}

check_os() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "Error: This script only supports Linux systems"
        exit 1
    fi
}

install_management_script() {
    echo ""
    echo "Installing management script..."
    echo ""

    local source_script=""
    local source_resolved=""
    local manager_resolved=""

    if [[ -n "${BASH_SOURCE[0]:-}" && -r "${BASH_SOURCE[0]}" && -f "${BASH_SOURCE[0]}" ]]; then
        source_script="${BASH_SOURCE[0]}"
        source_resolved=$(readlink -f "${source_script}" 2>/dev/null || echo "${source_script}")
        manager_resolved=$(readlink -f "${MANAGER_SCRIPT}" 2>/dev/null || true)

        # Make local script executable for reruns from current location.
        chmod +x "${source_script}" 2>/dev/null || true

        # Avoid copying a file onto itself when rerun from manager path.
        if [[ "${source_resolved}" != "${manager_resolved}" ]]; then
            cp -f "${source_script}" "${MANAGER_SCRIPT}"
        fi
    fi

    # Fallback for process substitution: bash <(curl ...).
    if [[ ! -s "${MANAGER_SCRIPT}" ]]; then
        curl -fsSL "${INSTALLER_URL}" -o "${MANAGER_SCRIPT}"
    fi

    chmod +x "${MANAGER_SCRIPT}"
}

is_yes() {
    local value
    value=$(echo "${1:-}" | tr '[:upper:]' '[:lower:]')
    [[ "$value" == "y" || "$value" == "yes" ]]
}

is_ip_literal() {
    local value="${1:-}"

    # IPv4
    if [[ "${value}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi

    # IPv6 (with or without [])
    value="${value#[}"
    value="${value%]}"
    if [[ "${value}" == *:* ]]; then
        return 0
    fi

    return 1
}

is_valid_tls_hostname() {
    local host="${1:-}"

    [[ -n "${host}" ]] || return 1
    [[ "${host}" =~ ^[A-Za-z0-9.-]+$ ]] || return 1
    [[ "${host}" == .* || "${host}" == *..* || "${host}" == *-.* || "${host}" == *.-* || "${host}" == *- ]] && return 1
    [[ "${host}" =~ [A-Za-z] ]] || return 1
    is_ip_literal "${host}" && return 1

    return 0
}

prompt_tls_hostname() {
    local suggested_default="${1:-}"
    local tls_hostname=""
    local default_tls_hostname="tt.local"

    if is_valid_tls_hostname "${suggested_default}"; then
        default_tls_hostname="${suggested_default}"
    fi

    while true; do
        read -r -p "Enter TLS hostname (domain-like, not IP) [${default_tls_hostname}]: " tls_hostname
        [ -z "${tls_hostname}" ] && tls_hostname="${default_tls_hostname}"

        if is_valid_tls_hostname "${tls_hostname}"; then
            echo "${tls_hostname}"
            return 0
        fi

        echo "Error: Invalid TLS hostname."
        echo "Use a domain-like value (for example: vpn.example.com or tt.local), not an IP address."
    done
}

extract_primary_cert_hostname() {
    local cert_path="$1"
    local san_dns=""
    local subject_line=""
    local cn_name=""

    san_dns=$(openssl x509 -in "${cert_path}" -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' \
        | sed -n 's/.*DNS:[[:space:]]*\([^[:space:]]*\).*/\1/p' \
        | head -n1)
    if [[ -n "${san_dns}" ]]; then
        echo "${san_dns}"
        return 0
    fi

    subject_line=$(openssl x509 -in "${cert_path}" -noout -subject 2>/dev/null || true)
    cn_name=$(echo "${subject_line}" | sed -n 's/.*CN[[:space:]]*=[[:space:]]*\([^,\/]*\).*/\1/p')
    if [[ -n "${cn_name}" ]]; then
        echo "${cn_name}"
        return 0
    fi

    echo ""
}

validate_certificate_and_key_pair() {
    local cert_path="$1"
    local key_path="$2"
    local cert_pub_hash=""
    local key_pub_hash=""

    [[ -f "${cert_path}" && -f "${key_path}" ]] || return 1

    openssl x509 -in "${cert_path}" -noout >/dev/null 2>&1 || return 1
    openssl pkey -in "${key_path}" -noout >/dev/null 2>&1 || return 1

    # Ignore expired certificates when presenting auto-discovered options.
    openssl x509 -in "${cert_path}" -checkend 0 -noout >/dev/null 2>&1 || return 1

    cert_pub_hash=$(openssl x509 -in "${cert_path}" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null \
        | openssl sha256 2>/dev/null \
        | sed 's/^.*= //')

    key_pub_hash=$(openssl pkey -in "${key_path}" -pubout -outform DER 2>/dev/null \
        | openssl sha256 2>/dev/null \
        | sed 's/^.*= //')

    [[ -n "${cert_pub_hash}" && -n "${key_pub_hash}" && "${cert_pub_hash}" == "${key_pub_hash}" ]]
}

certificate_pair_already_added() {
    local pair_key="$1"
    local existing=""

    for existing in "${FOUND_CERT_PAIR_KEYS[@]}"; do
        if [[ "${existing}" == "${pair_key}" ]]; then
            return 0
        fi
    done
    return 1
}

add_found_certificate_candidate() {
    local cert_path="$1"
    local key_path="$2"
    local source_label="$3"
    local pair_key="${cert_path}|${key_path}"
    local detected_hostname=""

    if certificate_pair_already_added "${pair_key}"; then
        return 0
    fi

    if ! validate_certificate_and_key_pair "${cert_path}" "${key_path}"; then
        return 0
    fi

    detected_hostname=$(extract_primary_cert_hostname "${cert_path}")
    if [[ -z "${detected_hostname}" ]]; then
        detected_hostname="unknown-hostname"
    fi

    FOUND_CERT_DOMAINS+=("${detected_hostname}")
    FOUND_CERT_PATHS+=("${cert_path}")
    FOUND_KEY_PATHS+=("${key_path}")
    FOUND_CERT_SOURCES+=("${source_label}")
    FOUND_CERT_PAIR_KEYS+=("${pair_key}")
    return 0
}

discover_common_certificate_pairs() {
    local dir=""
    local domain=""
    local cert=""
    local key=""
    local base_name=""

    FOUND_CERT_DOMAINS=()
    FOUND_CERT_PATHS=()
    FOUND_KEY_PATHS=()
    FOUND_CERT_SOURCES=()
    FOUND_CERT_PAIR_KEYS=()

    # 1) Let's Encrypt (certbot)
    for dir in /etc/letsencrypt/live/*; do
        [[ -d "${dir}" ]] || continue
        [[ -f "${dir}/fullchain.pem" && -f "${dir}/privkey.pem" ]] && add_found_certificate_candidate "${dir}/fullchain.pem" "${dir}/privkey.pem" "Let's Encrypt"
        [[ -f "${dir}/cert.pem" && -f "${dir}/privkey.pem" ]] && add_found_certificate_candidate "${dir}/cert.pem" "${dir}/privkey.pem" "Let's Encrypt"
    done

    # 2) acme.sh common layout
    for dir in /root/.acme.sh/*; do
        [[ -d "${dir}" ]] || continue
        domain=$(basename "${dir}")

        for cert in "${dir}/fullchain.cer" "${dir}/${domain}.cer" "${dir}/${domain}.crt" "${dir}/${domain}.pem"; do
            [[ -f "${cert}" ]] || continue
            for key in "${dir}/${domain}.key" "${dir}/private.key" "${dir}/privkey.pem"; do
                [[ -f "${key}" ]] || continue
                add_found_certificate_candidate "${cert}" "${key}" "acme.sh"
            done
        done
    done

    # 3) Custom common layout: /root/cert/<domain>/*
    if [[ -d /root/cert ]]; then
        for dir in /root/cert/*; do
            [[ -d "${dir}" ]] || continue
            domain=$(basename "${dir}")

            for cert in "${dir}/fullchain.pem" "${dir}/cert.pem" "${dir}/${domain}.crt" "${dir}/${domain}.pem" "${dir}/fullchain.cer"; do
                [[ -f "${cert}" ]] || continue
                for key in "${dir}/privkey.pem" "${dir}/key.pem" "${dir}/private.key" "${dir}/${domain}.key"; do
                    [[ -f "${key}" ]] || continue
                    add_found_certificate_candidate "${cert}" "${key}" "/root/cert"
                done
            done
        done

        # Also support flat files directly under /root/cert
        for cert in /root/cert/*.crt /root/cert/*.pem /root/cert/*.cer; do
            [[ -f "${cert}" ]] || continue
            base_name="${cert%.*}"
            for key in "${base_name}.key" /root/cert/privkey.pem /root/cert/key.pem /root/cert/private.key; do
                [[ -f "${key}" ]] || continue
                add_found_certificate_candidate "${cert}" "${key}" "/root/cert"
            done
        done
    fi

    # 4) Common manual locations used by nginx/apache/caddy installs.
    for dir in /etc/nginx/ssl /etc/apache2/ssl /etc/httpd/ssl /etc/caddy; do
        [[ -d "${dir}" ]] || continue
        for cert in "${dir}"/*.crt "${dir}"/*.pem "${dir}"/*.cer; do
            [[ -f "${cert}" ]] || continue
            base_name="${cert%.*}"
            for key in "${base_name}.key" "${dir}/privkey.pem" "${dir}/private.key"; do
                [[ -f "${key}" ]] || continue
                add_found_certificate_candidate "${cert}" "${key}" "Web Server"
            done
        done
    done

    # 5) Debian/Ubuntu-style SSL cert+key names.
    for key in /etc/ssl/private/*.key; do
        [[ -f "${key}" ]] || continue
        base_name=$(basename "${key}" .key)
        for cert in "/etc/ssl/certs/${base_name}.crt" "/etc/ssl/certs/${base_name}.pem"; do
            [[ -f "${cert}" ]] || continue
            add_found_certificate_candidate "${cert}" "${key}" "System SSL"
        done
    done

    return 0
}

prompt_custom_existing_certificate_paths() {
    local detected_hostname=""

    while true; do
        echo ""
        read -r -p "Enter path to certificate chain (cert.pem): " CERT_PATH
        read -r -p "Enter path to private key (key.pem): " KEY_PATH

        if [[ ! -f "${CERT_PATH}" || ! -f "${KEY_PATH}" ]]; then
            echo "Error: Certificate files not found"
            continue
        fi

        if ! validate_certificate_and_key_pair "${CERT_PATH}" "${KEY_PATH}"; then
            echo "Error: Invalid certificate/key pair (mismatch, unreadable key, or expired certificate)"
            continue
        fi

        detected_hostname=$(extract_primary_cert_hostname "${CERT_PATH}")
        DOMAIN_NAME=$(prompt_tls_hostname "${detected_hostname}")
        return 0
    done
}

collect_existing_certificate_paths() {
    local candidate_count=0
    local custom_choice=0
    local selection=""
    local idx=0

    if ! command -v openssl >/dev/null 2>&1; then
        echo "Warning: openssl not found. Falling back to manual certificate path input."
        prompt_custom_existing_certificate_paths
        return 0
    fi

    echo ""
    echo "Scanning common certificate locations..."
    discover_common_certificate_pairs

    candidate_count=${#FOUND_CERT_PATHS[@]}
    if (( candidate_count == 0 )); then
        echo "No valid certificate/key pairs found in common locations."
        prompt_custom_existing_certificate_paths
        return 0
    fi

    echo ""
    echo "Found valid certificates:"
    for ((idx = 0; idx < candidate_count; idx++)); do
        echo "$((idx + 1))) ${FOUND_CERT_DOMAINS[$idx]} [${FOUND_CERT_SOURCES[$idx]}]"
        echo "   cert: ${FOUND_CERT_PATHS[$idx]}"
        echo "   key : ${FOUND_KEY_PATHS[$idx]}"
    done

    custom_choice=$((candidate_count + 1))
    echo "${custom_choice}) Enter custom certificate/key paths"
    echo ""

    while true; do
        read -r -p "Choose certificate option (or press enter for [${custom_choice}]): " selection
        [ -z "${selection}" ] && selection="${custom_choice}"

        if [[ "${selection}" =~ ^[0-9]+$ ]] && (( selection >= 1 && selection <= candidate_count )); then
            idx=$((selection - 1))
            CERT_PATH="${FOUND_CERT_PATHS[$idx]}"
            KEY_PATH="${FOUND_KEY_PATHS[$idx]}"
            echo "Selected certificate for: ${FOUND_CERT_DOMAINS[$idx]}"
            DOMAIN_NAME=$(prompt_tls_hostname "${FOUND_CERT_DOMAINS[$idx]}")
            return 0
        fi

        if [[ "${selection}" =~ ^[0-9]+$ ]] && (( selection == custom_choice )); then
            prompt_custom_existing_certificate_paths
            return 0
        fi

        echo "Error: Invalid choice"
    done

    return 0
}

get_installer_mode() {
    if [[ -f "${MODE_MARKER}" ]]; then
        # shellcheck source=/dev/null
        source "${MODE_MARKER}"
        echo "${MODE:-}"
        return
    fi

    # Backward compatibility for older endpoint-only installs.
    if is_installed && is_configured; then
        echo "standalone"
        return
    fi

    echo ""
}

set_installer_mode() {
    local mode="$1"
    cat > "${MODE_MARKER}" << EOF
MODE=${mode}
UPDATED_AT=$(date -Iseconds)
EOF
    chmod 600 "${MODE_MARKER}"
}

clear_installer_mode() {
    rm -f "${MODE_MARKER}"
}

is_client_installed() {
    [[ -f "${CLIENT_INSTALL_DIR}/trusttunnel_client" ]]
}

is_client_configured() {
    [[ -f "${CLIENT_CONFIG_FILE}" && -f "${CLIENT_MARKER_FILE}" ]]
}

is_client_service_running() {
    systemctl is-active --quiet ${CLIENT_SERVICE_NAME} 2>/dev/null
}

is_client_service_enabled() {
    systemctl is-enabled --quiet ${CLIENT_SERVICE_NAME} 2>/dev/null
}

get_public_ip() {
    curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "Unable to detect"
}

get_arch() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|x86-64|x64|amd64)
            echo "x86_64"
            ;;
        aarch64|arm64)
            echo "aarch64"
            ;;
        *)
            echo "unsupported"
            ;;
    esac
}

is_installed() {
    [[ -f "${INSTALL_DIR}/trusttunnel_endpoint" ]]
}

is_configured() {
    [[ -f "${MARKER_FILE}" ]]
}

is_service_running() {
    systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null
}

is_service_enabled() {
    systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null
}

generate_random_password() {
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16
}

# ============================================================================
# Installation Functions
# ============================================================================

install_trusttunnel() {
    echo ""
    echo "Installing TrustTunnel..."
    echo ""
    
    local arch
    arch=$(get_arch)
    if [[ "$arch" == "unsupported" ]]; then
        echo "Error: Unsupported architecture: $(uname -m)"
        echo "TrustTunnel supports x86_64 and aarch64 architectures"
        exit 1
    fi
    
    echo "Detected architecture: $arch"
    echo "Downloading TrustTunnel..."
    echo ""
    
    # Download and install using official script
    curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s -- -a y
    
    if is_installed; then
        echo "TrustTunnel installed successfully to ${INSTALL_DIR}"
    else
        echo "Error: Installation failed"
        exit 1
    fi
}

install_trusttunnel_client() {
    echo ""
    echo "Installing TrustTunnel Client..."
    echo ""

    local arch
    arch=$(get_arch)
    if [[ "$arch" == "unsupported" ]]; then
        echo "Error: Unsupported architecture: $(uname -m)"
        echo "TrustTunnel Client supports x86_64 and aarch64 architectures"
        exit 1
    fi

    curl -fsSL "${CLIENT_INSTALL_URL}" | sh -s -- -o "${CLIENT_INSTALL_DIR}" -a y

    if is_client_installed; then
        echo "TrustTunnel Client installed successfully to ${CLIENT_INSTALL_DIR}"
    else
        echo "Error: TrustTunnel Client installation failed"
        exit 1
    fi
}

# ============================================================================
# Configuration Functions
# ============================================================================

collect_configuration() {
    echo ""
    echo "Configuration"
    echo ""
    
    local public_ip
    public_ip=$(get_public_ip)
    
    echo "Please provide the following configuration details:"
    echo ""
    
    # Listen Address
    read -r -p "Enter listen address (or press enter for default [0.0.0.0:443]): " LISTEN_ADDRESS
    [ -z "$LISTEN_ADDRESS" ] && LISTEN_ADDRESS="0.0.0.0:443"
    
    # Extract port from listen address
    LISTEN_PORT=$(echo "$LISTEN_ADDRESS" | grep -oP ':\K[0-9]+$' || echo "443")
    
    # Public IP/Domain for client config
    echo ""
    echo "Your detected public IP: ${public_ip}"
    read -r -p "Enter public IP or domain for client connections (or press enter for [$public_ip]): " PUBLIC_ADDRESS
    [ -z "$PUBLIC_ADDRESS" ] && PUBLIC_ADDRESS="$public_ip"
    
    # Username
    echo ""
    read -r -p "Enter VPN username (or press enter for [admin]): " VPN_USERNAME
    [ -z "$VPN_USERNAME" ] && VPN_USERNAME="admin"
    
    # Password
    local default_password
    default_password=$(generate_random_password)
    echo ""
    read -r -p "Enter VPN password (or press enter for random [$default_password]): " VPN_PASSWORD
    [ -z "$VPN_PASSWORD" ] && VPN_PASSWORD="$default_password"
    
    # Certificate Type
    echo ""
    echo "Certificate Options:"
    echo ""
    echo "1) Let's Encrypt (requires valid domain pointing to this server)"
    echo ""
    echo "2) Self-signed certificate (for testing or CLI client only)"
    echo ""
    echo "3) Existing certificate (provide paths)"
    echo ""
    read -r -p "Choose certificate option (or press enter for [2]): " CERT_OPTION
    [ -z "$CERT_OPTION" ] && CERT_OPTION=2
    
    case "$CERT_OPTION" in
        1)
            CERT_TYPE="letsencrypt"
            echo ""
            read -r -p "Enter domain name (must point to this server): " DOMAIN_NAME
            if ! is_valid_tls_hostname "${DOMAIN_NAME}"; then
                echo "Error: A valid domain-like hostname is required for Let's Encrypt"
                exit 1
            fi
            read -r -p "Enter email for Let's Encrypt notifications: " LE_EMAIL
            export LE_EMAIL
            ;;
        2)
            CERT_TYPE="selfsigned"
            echo ""
            echo "TLS hostname is used for endpoint SNI/certificate and must not be an IP."
            DOMAIN_NAME=$(prompt_tls_hostname "${PUBLIC_ADDRESS}")
            ;;
        3)
            CERT_TYPE="existing"
            echo ""
            collect_existing_certificate_paths
            ;;
        *)
            echo "Error: Invalid option"
            exit 1
            ;;
    esac
    
    # IPv6 Support
    echo ""
    read -r -p "Enable IPv6 routing? [y/N]: " ENABLE_IPV6
    ENABLE_IPV6=$(echo "${ENABLE_IPV6:-n}" | tr '[:upper:]' '[:lower:]')
    [[ "$ENABLE_IPV6" == "y" ]] && IPV6_AVAILABLE="true" || IPV6_AVAILABLE="false"

    # Advanced network settings
    echo ""
    echo "Transport Protocols (recommended: enable all)"
    while true; do
        read -r -p "Enable HTTP/1.1? [Y/n]: " ENABLE_HTTP1
        ENABLE_HTTP1=$(echo "${ENABLE_HTTP1:-y}" | tr '[:upper:]' '[:lower:]')
        [[ "$ENABLE_HTTP1" == "y" || "$ENABLE_HTTP1" == "yes" ]] && HTTP1_ENABLED="true" || HTTP1_ENABLED="false"

        read -r -p "Enable HTTP/2? [Y/n]: " ENABLE_HTTP2
        ENABLE_HTTP2=$(echo "${ENABLE_HTTP2:-y}" | tr '[:upper:]' '[:lower:]')
        [[ "$ENABLE_HTTP2" == "y" || "$ENABLE_HTTP2" == "yes" ]] && HTTP2_ENABLED="true" || HTTP2_ENABLED="false"

        read -r -p "Enable QUIC/HTTP3? [Y/n]: " ENABLE_QUIC
        ENABLE_QUIC=$(echo "${ENABLE_QUIC:-y}" | tr '[:upper:]' '[:lower:]')
        [[ "$ENABLE_QUIC" == "y" || "$ENABLE_QUIC" == "yes" ]] && QUIC_ENABLED="true" || QUIC_ENABLED="false"

        if [[ "$HTTP1_ENABLED" == "true" || "$HTTP2_ENABLED" == "true" || "$QUIC_ENABLED" == "true" ]]; then
            break
        fi

        echo "Error: At least one protocol must be enabled"
    done

    PROTOCOLS=""
    [[ "${HTTP1_ENABLED}" == "true" ]] && PROTOCOLS="HTTP/1.1"
    if [[ "${HTTP2_ENABLED}" == "true" ]]; then
        [[ -n "${PROTOCOLS}" ]] && PROTOCOLS="${PROTOCOLS}, "
        PROTOCOLS="${PROTOCOLS}HTTP/2"
    fi
    if [[ "${QUIC_ENABLED}" == "true" ]]; then
        [[ -n "${PROTOCOLS}" ]] && PROTOCOLS="${PROTOCOLS}, "
        PROTOCOLS="${PROTOCOLS}QUIC/HTTP3"
    fi

    echo ""
    read -r -p "Allow access to endpoint private network? [y/N]: " ALLOW_PRIVATE_NETWORK_INPUT
    ALLOW_PRIVATE_NETWORK_INPUT=$(echo "${ALLOW_PRIVATE_NETWORK_INPUT:-n}" | tr '[:upper:]' '[:lower:]')
    [[ "$ALLOW_PRIVATE_NETWORK_INPUT" == "y" || "$ALLOW_PRIVATE_NETWORK_INPUT" == "yes" ]] && ALLOW_PRIVATE_NETWORK="true" || ALLOW_PRIVATE_NETWORK="false"

    echo ""
    echo "Forwarding Mode:"
    echo "1) Direct (default)"
    echo "2) SOCKS5 upstream proxy"
    read -r -p "Choose forwarding mode (or press enter for [1]): " FORWARD_OPTION
    [ -z "$FORWARD_OPTION" ] && FORWARD_OPTION=1
    case "$FORWARD_OPTION" in
        1)
            FORWARD_MODE="direct"
            ;;
        2)
            FORWARD_MODE="socks5"
            read -r -p "Enter SOCKS5 server address [127.0.0.1:1080]: " SOCKS5_ADDRESS
            [ -z "$SOCKS5_ADDRESS" ] && SOCKS5_ADDRESS="127.0.0.1:1080"
            read -r -p "Enable SOCKS5 extended authentication? [y/N]: " SOCKS5_EXTENDED_AUTH_INPUT
            SOCKS5_EXTENDED_AUTH_INPUT=$(echo "${SOCKS5_EXTENDED_AUTH_INPUT:-n}" | tr '[:upper:]' '[:lower:]')
            [[ "$SOCKS5_EXTENDED_AUTH_INPUT" == "y" || "$SOCKS5_EXTENDED_AUTH_INPUT" == "yes" ]] && SOCKS5_EXTENDED_AUTH="true" || SOCKS5_EXTENDED_AUTH="false"
            ;;
        *)
            echo "Error: Invalid forwarding mode"
            exit 1
            ;;
    esac

    # Show configuration summary
    echo ""
    echo "Configuration Summary:"
    echo ""
    echo "  Listen Address:    ${LISTEN_ADDRESS}"
    echo "  Public Address:    ${PUBLIC_ADDRESS}"
    echo "  Username:          ${VPN_USERNAME}"
    echo "  Password:          ${VPN_PASSWORD}"
    echo "  Certificate:       ${CERT_TYPE}"
    echo "  Domain:            ${DOMAIN_NAME}"
    echo "  IPv6 Enabled:      ${IPV6_AVAILABLE}"
    echo "  Protocols:         ${PROTOCOLS}"
    echo "  HTTP/1.1:          ${HTTP1_ENABLED}"
    echo "  HTTP/2:            ${HTTP2_ENABLED}"
    echo "  QUIC/HTTP3:        ${QUIC_ENABLED}"
    echo "  Private Network:   ${ALLOW_PRIVATE_NETWORK}"
    echo "  Forward Mode:      ${FORWARD_MODE}"
    if [[ "${FORWARD_MODE}" == "socks5" ]]; then
        echo "  SOCKS5 Address:    ${SOCKS5_ADDRESS}"
        echo "  SOCKS5 Ext Auth:   ${SOCKS5_EXTENDED_AUTH}"
    fi
    echo ""
    
    read -r -p "Proceed with this configuration? [Y/n]: " CONFIRM
    CONFIRM=$(echo "${CONFIRM:-y}" | tr '[:upper:]' '[:lower:]')
    if [[ "$CONFIRM" != "y" ]]; then
        echo "Configuration cancelled"
        exit 0
    fi
}

create_configuration_files() {
    echo ""
    echo "Creating Configuration Files..."
    echo ""
    
    cd "${INSTALL_DIR}"
    
    # Create certificates directory
    mkdir -p "${CONFIG_DIR}/certs"
    
    # Handle certificate generation/setup
    case "$CERT_TYPE" in
        "selfsigned")
            echo "Generating self-signed certificate..."
            openssl req -x509 -newkey rsa:4096 -keyout "${CONFIG_DIR}/certs/key.pem" \
                -out "${CONFIG_DIR}/certs/cert.pem" -days 365 -nodes \
                -subj "/CN=${DOMAIN_NAME}" 2>/dev/null
            CERT_CHAIN_PATH="${CONFIG_DIR}/certs/cert.pem"
            PRIVATE_KEY_PATH="${CONFIG_DIR}/certs/key.pem"
            echo "Self-signed certificate generated"
            ;;
        "existing")
            cp "$CERT_PATH" "${CONFIG_DIR}/certs/cert.pem"
            cp "$KEY_PATH" "${CONFIG_DIR}/certs/key.pem"
            CERT_CHAIN_PATH="${CONFIG_DIR}/certs/cert.pem"
            PRIVATE_KEY_PATH="${CONFIG_DIR}/certs/key.pem"
            echo "Certificate files copied"
            ;;
        "letsencrypt")
            echo "Setting up Let's Encrypt certificate..."
            echo "For Let's Encrypt, please run the setup wizard manually after installation:"
            echo "  cd ${INSTALL_DIR} && sudo ./setup_wizard"
            CERT_CHAIN_PATH="${CONFIG_DIR}/certs/cert.pem"
            PRIVATE_KEY_PATH="${CONFIG_DIR}/certs/key.pem"
            touch "${CONFIG_DIR}/certs/cert.pem"
            touch "${CONFIG_DIR}/certs/key.pem"
            ;;
    esac
    
    # Create vpn.toml (main settings)
    echo "Creating vpn.toml..."
    cat > "${CONFIG_DIR}/vpn.toml" << EOF
# TrustTunnel VPN Endpoint Configuration
# Generated by TrustTunnel Manager

# The address to listen on
listen_address = "${LISTEN_ADDRESS}"

# Whether IPv6 connections can be routed
ipv6_available = ${IPV6_AVAILABLE}

# Whether connections to private network of the endpoint are allowed
allow_private_network_connections = ${ALLOW_PRIVATE_NETWORK}

# Timeout of an incoming TLS handshake (seconds)
tls_handshake_timeout_secs = 10

# Timeout of a client listener (seconds)
client_listener_timeout_secs = 600

# Timeout of outgoing connection establishment (seconds)
connection_establishment_timeout_secs = 30

# Idle timeout of tunneled TCP connections (seconds)
tcp_connections_timeout_secs = 604800

# Timeout of tunneled UDP "connections" (seconds)
udp_connections_timeout_secs = 300

# Path to credentials file
credentials_file = "credentials.toml"

# Path to rules file (optional)
rules_file = "rules.toml"

# Listen protocol settings
[listen_protocols]
EOF

    if [[ "${HTTP1_ENABLED}" == "true" ]]; then
        cat >> "${CONFIG_DIR}/vpn.toml" << 'EOF'

[listen_protocols.http1]
upload_buffer_size = 32768
EOF
    fi

    if [[ "${HTTP2_ENABLED}" == "true" ]]; then
        cat >> "${CONFIG_DIR}/vpn.toml" << 'EOF'

[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 131072
max_concurrent_streams = 1000
max_frame_size = 16384
header_table_size = 65536
EOF
    fi

    if [[ "${QUIC_ENABLED}" == "true" ]]; then
        cat >> "${CONFIG_DIR}/vpn.toml" << 'EOF'

[listen_protocols.quic]
recv_udp_payload_size = 1350
send_udp_payload_size = 1350
initial_max_data = 104857600
initial_max_stream_data_bidi_local = 1048576
initial_max_stream_data_bidi_remote = 1048576
initial_max_stream_data_uni = 1048576
initial_max_streams_bidi = 4096
initial_max_streams_uni = 4096
max_connection_window = 25165824
max_stream_window = 16777216
disable_active_migration = true
enable_early_data = true
message_queue_capacity = 4096
EOF
    fi

    if [[ "${FORWARD_MODE}" == "socks5" ]]; then
        cat >> "${CONFIG_DIR}/vpn.toml" << EOF

# Forward protocol
[forward_protocol.socks5]
address = "${SOCKS5_ADDRESS}"
extended_auth = ${SOCKS5_EXTENDED_AUTH}
EOF
    else
        cat >> "${CONFIG_DIR}/vpn.toml" << 'EOF'

# Forward protocol
[forward_protocol]
direct = {}
EOF
    fi

    echo "vpn.toml created"
    
    # Create hosts.toml (TLS hosts settings)
    echo "Creating hosts.toml..."
    cat > "${CONFIG_DIR}/hosts.toml" << EOF
# TrustTunnel TLS Hosts Configuration
# Generated by TrustTunnel Manager

[[main_hosts]]
hostname = "${DOMAIN_NAME}"
cert_chain_path = "${CERT_CHAIN_PATH}"
private_key_path = "${PRIVATE_KEY_PATH}"
EOF
    echo "hosts.toml created"
    
    # Create credentials.toml
    echo "Creating credentials.toml..."
    cat > "${CONFIG_DIR}/credentials.toml" << EOF
# TrustTunnel User Credentials
# Generated by TrustTunnel Manager

[[client]]
username = "${VPN_USERNAME}"
password = "${VPN_PASSWORD}"
EOF
    chmod 600 "${CONFIG_DIR}/credentials.toml"
    echo "credentials.toml created"
    
    # Create rules.toml (allow all by default)
    echo "Creating rules.toml..."
    cat > "${CONFIG_DIR}/rules.toml" << EOF
# TrustTunnel Connection Rules
# Generated by TrustTunnel Manager
# No rules defined - all connections are allowed by default
EOF
    echo "rules.toml created"
    
    # Create marker file with configuration info
    cat > "${MARKER_FILE}" << EOF
# TrustTunnel Configuration Marker
# Created: $(date)
PUBLIC_ADDRESS=${PUBLIC_ADDRESS}
LISTEN_PORT=${LISTEN_PORT}
VPN_USERNAME=${VPN_USERNAME}
CERT_TYPE=${CERT_TYPE}
DOMAIN_NAME=${DOMAIN_NAME}
HTTP1_ENABLED=${HTTP1_ENABLED}
HTTP2_ENABLED=${HTTP2_ENABLED}
QUIC_ENABLED=${QUIC_ENABLED}
ALLOW_PRIVATE_NETWORK=${ALLOW_PRIVATE_NETWORK}
FORWARD_MODE=${FORWARD_MODE}
SOCKS5_ADDRESS=${SOCKS5_ADDRESS}
SOCKS5_EXTENDED_AUTH=${SOCKS5_EXTENDED_AUTH}
EOF
    chmod 600 "${MARKER_FILE}"
}

setup_systemd_service() {
    echo ""
    echo "Setting Up Systemd Service..."
    echo ""
    
    # Create systemd service file
    cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=TrustTunnel VPN Endpoint
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/trusttunnel_endpoint vpn.toml hosts.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    echo "Systemd service file created"
    
    # Reload systemd
    if ! systemctl daemon-reload; then
        echo "Error: Failed to reload systemd daemon"
        return 1
    fi
    echo "Systemd daemon reloaded"
    
    # Enable service
    if ! systemctl enable ${SERVICE_NAME}; then
        echo "Error: Failed to enable ${SERVICE_NAME} service"
        return 1
    fi
    echo "Service enabled to start on boot"
}

start_service() {
    echo "Starting TrustTunnel service..."
    if ! systemctl start ${SERVICE_NAME}; then
        echo "Error: Failed to start ${SERVICE_NAME} service"
        echo "Check logs with: journalctl -u ${SERVICE_NAME} -f"
        return 1
    fi
    sleep 2
    
    if is_service_running; then
        echo "TrustTunnel service is running"
    else
        echo "Error: Failed to start TrustTunnel service"
        echo "Check logs with: journalctl -u ${SERVICE_NAME} -f"
    fi
}

stop_service() {
    echo "Stopping TrustTunnel service..."
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    echo "Service stopped"
}

setup_client_systemd_service() {
    echo ""
    echo "Setting Up TrustTunnel Client Service..."
    echo ""

    cat > "${CLIENT_SERVICE_FILE}" << EOF
[Unit]
Description=TrustTunnel Client Relay
After=network.target

[Service]
Type=simple
WorkingDirectory=${CLIENT_INSTALL_DIR}
ExecStart=${CLIENT_INSTALL_DIR}/trusttunnel_client --config ${CLIENT_CONFIG_FILE}
# The client should stay up continuously for SOCKS access.
# Some runtime paths can exit cleanly; always restart to keep service availability.
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    if ! systemctl daemon-reload; then
        echo "Error: Failed to reload systemd daemon"
        return 1
    fi
    if ! systemctl enable ${CLIENT_SERVICE_NAME}; then
        echo "Error: Failed to enable ${CLIENT_SERVICE_NAME} service"
        return 1
    fi
    echo "TrustTunnel Client service enabled"
}

start_client_service() {
    echo "Starting TrustTunnel Client service..."
    if ! systemctl start ${CLIENT_SERVICE_NAME}; then
        echo "Error: Failed to start ${CLIENT_SERVICE_NAME} service"
        echo "Check logs with: journalctl -u ${CLIENT_SERVICE_NAME} -f"
        return 1
    fi
    sleep 2

    if is_client_service_running; then
        echo "TrustTunnel Client service is running"
    else
        echo "Error: Failed to start TrustTunnel Client service"
        echo "Check logs with: journalctl -u ${CLIENT_SERVICE_NAME} -f"
    fi
}

stop_client_service() {
    echo "Stopping TrustTunnel Client service..."
    systemctl stop ${CLIENT_SERVICE_NAME} 2>/dev/null || true
    echo "TrustTunnel Client service stopped"
}

show_client_config() {
    if [[ ! -f "${MARKER_FILE}" ]]; then
        echo "Error: Configuration not found"
        return
    fi
    
    # shellcheck source=/dev/null
    source "${MARKER_FILE}"
    
    echo ""
    echo "Client Configuration"
    echo ""
    
    cd "${INSTALL_DIR}"
    
    local client_address="${PUBLIC_ADDRESS}"
    if [[ "${LISTEN_PORT}" != "443" ]]; then
        client_address="${PUBLIC_ADDRESS}:${LISTEN_PORT}"
    fi
    
    echo "Generating client configuration for '${VPN_USERNAME}'..."
    echo ""
    
    if [[ -f "${INSTALL_DIR}/trusttunnel_endpoint" ]]; then
        ${INSTALL_DIR}/trusttunnel_endpoint vpn.toml hosts.toml -c "${VPN_USERNAME}" -a "${client_address}" 2>/dev/null || {
            echo "Could not generate client config. Manual connection info:"
            echo ""
            echo "  Server:   ${client_address}"
            echo "  Username: ${VPN_USERNAME}"
            echo "  Password: (check credentials.toml)"
        }
    fi
    
    echo ""
    echo "Use this configuration in TrustTunnel Flutter Client or CLI Client"
}

escape_toml_string() {
    printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

generate_mainland_bundle_token() {
    if [[ ! -f "${MARKER_FILE}" ]]; then
        echo "Error: Endpoint configuration marker not found"
        return 1
    fi

    if [[ ! -f "${INSTALL_DIR}/trusttunnel_endpoint" ]]; then
        echo "Error: trusttunnel_endpoint binary not found"
        return 1
    fi

    # shellcheck source=/dev/null
    source "${MARKER_FILE}"

    local bundle_username="${VPN_USERNAME:-}"
    local client_address="${PUBLIC_ADDRESS}"
    local client_config=""
    local bundle_payload=""
    local bundle_token=""

    if [[ -z "${bundle_username}" && -f "${CONFIG_DIR}/credentials.toml" ]]; then
        bundle_username=$(sed -n 's/^[[:space:]]*username[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${CONFIG_DIR}/credentials.toml" | head -n1)
    fi

    if [[ -z "${bundle_username}" ]]; then
        echo "Error: Could not determine a username for bundle export"
        return 1
    fi

    if [[ "${LISTEN_PORT}" != "443" ]]; then
        client_address="${PUBLIC_ADDRESS}:${LISTEN_PORT}"
    fi

    client_config=$("${INSTALL_DIR}/trusttunnel_endpoint" vpn.toml hosts.toml -c "${bundle_username}" -a "${client_address}" 2>/dev/null || true)
    if [[ -z "${client_config}" ]]; then
        echo "Error: Failed to export endpoint config for '${bundle_username}'"
        return 1
    fi

    bundle_payload=$(printf '%s' "${client_config}" | gzip -9 | base64 | tr -d '\n')
    bundle_token="${BUNDLE_PREFIX}.${bundle_payload}"

    printf '%s\n' "${bundle_token}" > "${BUNDLE_FILE}"
    chmod 600 "${BUNDLE_FILE}"

    echo ""
    echo "Mainland Bundle Token"
    echo ""
    echo "Saved to: ${BUNDLE_FILE}"
    echo ""
    echo "${bundle_token}"
    echo ""
    echo "Use this token on the mainland host in Tunnel Mode -> Mainland Relay Client."
    return 0
}

decode_bundle_token_to_file() {
    local token_input="$1"
    local output_file="$2"
    local token_clean=""
    local payload=""

    token_clean=$(printf '%s' "${token_input}" | tr -d '[:space:]')
    payload="${token_clean}"
    if [[ "${token_clean}" == "${BUNDLE_PREFIX}."* ]]; then
        payload="${token_clean#"${BUNDLE_PREFIX}."}"
    fi

    if ! printf '%s' "${payload}" | base64 -d 2>/dev/null | gunzip > "${output_file}" 2>/dev/null; then
        return 1
    fi

    if ! grep -q '^[[:space:]]*hostname[[:space:]]*=' "${output_file}"; then
        return 1
    fi

    return 0
}

build_mainland_endpoint_config_from_manual() {
    local output_file="$1"
    local cert_file=""
    local cert_content=""
    local manual_hostname=""
    local manual_address=""
    local manual_username=""
    local manual_password=""
    local manual_has_ipv6="true"
    local manual_skip_verification="false"
    local manual_upstream_protocol="http2"
    local manual_upstream_fallback=""
    local manual_anti_dpi="false"
    local answer=""

    echo ""
    echo "Manual Foreign Endpoint Settings"
    echo ""
    read -r -p "Foreign endpoint TLS hostname (domain-like, not IP): " manual_hostname
    if ! is_valid_tls_hostname "${manual_hostname}"; then
        echo "Error: Invalid endpoint hostname."
        echo "Use a domain-like value (for example: vpn.example.com or tt.local), not an IP address."
        return 1
    fi
    read -r -p "Foreign endpoint address (ip:port): " manual_address
    read -r -p "Username: " manual_username
    read -r -p "Password: " manual_password
    read -r -p "Endpoint supports IPv6? [Y/n]: " answer
    is_yes "${answer:-y}" && manual_has_ipv6="true" || manual_has_ipv6="false"
    read -r -p "Skip certificate verification? [y/N]: " answer
    is_yes "${answer:-n}" && manual_skip_verification="true" || manual_skip_verification="false"
    read -r -p "Upstream protocol [http2/http3] (default [http2]): " manual_upstream_protocol
    [ -z "${manual_upstream_protocol}" ] && manual_upstream_protocol="http2"
    export MANUAL_UPSTREAM_PROTOCOL="${manual_upstream_protocol}"
    if [[ "${manual_upstream_protocol}" != "http2" && "${manual_upstream_protocol}" != "http3" ]]; then
        echo "Error: invalid upstream protocol"
        return 1
    fi
    read -r -p "Fallback protocol [none/http2/http3] (default [none]): " manual_upstream_fallback
    [ -z "${manual_upstream_fallback}" ] && manual_upstream_fallback="none"
    if [[ "${manual_upstream_fallback}" == "none" ]]; then
        manual_upstream_fallback=""
    elif [[ "${manual_upstream_fallback}" != "http2" && "${manual_upstream_fallback}" != "http3" ]]; then
        echo "Error: invalid fallback protocol"
        return 1
    fi
    export MANUAL_UPSTREAM_FALLBACK="${manual_upstream_fallback}"
    read -r -p "Enable anti-DPI? [y/N]: " answer
    is_yes "${answer:-n}" && manual_anti_dpi="true" || manual_anti_dpi="false"
    export MANUAL_ANTI_DPI="${manual_anti_dpi}"

    read -r -p "Path to endpoint certificate PEM (required): " cert_file
    if [[ -z "${cert_file}" || ! -f "${cert_file}" ]]; then
        echo "Error: certificate file is required and must exist"
        return 1
    fi
    cert_content=$(cat "${cert_file}")

    cat > "${output_file}" << EOF
hostname = "$(escape_toml_string "${manual_hostname}")"
addresses = ["$(escape_toml_string "${manual_address}")"]
has_ipv6 = ${manual_has_ipv6}
username = "$(escape_toml_string "${manual_username}")"
password = "$(escape_toml_string "${manual_password}")"
client_random = ""
skip_verification = ${manual_skip_verification}
certificate = """${cert_content}"""
upstream_protocol = "${manual_upstream_protocol}"
upstream_fallback_protocol = "${manual_upstream_fallback}"
anti_dpi = ${manual_anti_dpi}
EOF

    return 0
}

collect_mainland_client_configuration() {
    local endpoint_config_file="${CLIENT_INSTALL_DIR}/endpoint_config.toml"
    local source_choice=""
    local token_input=""
    local config_path=""
    local bind_choice=""
    local answer=""
    local default_password=""

    mkdir -p "${CLIENT_INSTALL_DIR}"

    echo ""
    echo "Mainland Relay Setup"
    echo ""
    echo "How do you want to import foreign endpoint settings?"
    echo "1) Bundle token (recommended)"
    echo "2) Existing endpoint config file"
    echo "3) Manual input"
    echo ""
    read -r -p "Choose option (or press enter for [1]): " source_choice
    [ -z "${source_choice}" ] && source_choice=1

    case "${source_choice}" in
        1)
            read -r -p "Paste bundle token: " token_input
            if ! decode_bundle_token_to_file "${token_input}" "${endpoint_config_file}"; then
                echo "Error: Invalid bundle token"
                exit 1
            fi
            MAINLAND_SOURCE_TYPE="bundle"
            ;;
        2)
            read -r -p "Enter path to endpoint config file: " config_path
            if [[ ! -f "${config_path}" ]]; then
                echo "Error: File not found"
                exit 1
            fi
            cp -f "${config_path}" "${endpoint_config_file}"
            MAINLAND_SOURCE_TYPE="file"
            ;;
        3)
            if ! build_mainland_endpoint_config_from_manual "${endpoint_config_file}"; then
                exit 1
            fi
            MAINLAND_SOURCE_TYPE="manual"
            # These were already collected in build_mainland_endpoint_config_from_manual
            MAINLAND_UPSTREAM_PROTOCOL="${MANUAL_UPSTREAM_PROTOCOL:-http2}"
            MAINLAND_UPSTREAM_FALLBACK="${MANUAL_UPSTREAM_FALLBACK:-}"
            MAINLAND_ANTI_DPI="${MANUAL_ANTI_DPI:-false}"
            ;;
        *)
            echo "Error: Invalid option"
            exit 1
            ;;
    esac

    ENDPOINT_CONFIG_SOURCE_FILE="${endpoint_config_file}"

    # Only ask for protocol settings if not already collected (manual input already has them)
    if [[ "${MAINLAND_SOURCE_TYPE}" != "manual" ]]; then
        read -r -p "Client upstream protocol [http2/http3] (default [http2]): " MAINLAND_UPSTREAM_PROTOCOL
        [ -z "${MAINLAND_UPSTREAM_PROTOCOL}" ] && MAINLAND_UPSTREAM_PROTOCOL="http2"
        if [[ "${MAINLAND_UPSTREAM_PROTOCOL}" != "http2" && "${MAINLAND_UPSTREAM_PROTOCOL}" != "http3" ]]; then
            echo "Error: Invalid upstream protocol"
            exit 1
        fi

        read -r -p "Fallback protocol [none/http2/http3] (default [none]): " MAINLAND_UPSTREAM_FALLBACK
        [ -z "${MAINLAND_UPSTREAM_FALLBACK}" ] && MAINLAND_UPSTREAM_FALLBACK="none"
        if [[ "${MAINLAND_UPSTREAM_FALLBACK}" == "none" ]]; then
            MAINLAND_UPSTREAM_FALLBACK=""
        elif [[ "${MAINLAND_UPSTREAM_FALLBACK}" != "http2" && "${MAINLAND_UPSTREAM_FALLBACK}" != "http3" ]]; then
            echo "Error: Invalid fallback protocol"
            exit 1
        fi

        read -r -p "Enable anti-DPI? [y/N]: " answer
        is_yes "${answer:-n}" && MAINLAND_ANTI_DPI="true" || MAINLAND_ANTI_DPI="false"
    fi

    read -r -p "SOCKS listen port (default [1080]): " MAINLAND_SOCKS_PORT
    [ -z "${MAINLAND_SOCKS_PORT}" ] && MAINLAND_SOCKS_PORT="1080"
    if ! [[ "${MAINLAND_SOCKS_PORT}" =~ ^[0-9]+$ ]] || (( MAINLAND_SOCKS_PORT < 1 || MAINLAND_SOCKS_PORT > 65535 )); then
        echo "Error: Invalid SOCKS port. Use a number between 1 and 65535."
        exit 1
    fi

    echo ""
    echo "SOCKS5 Bind Mode:"
    echo "1) Localhost only (127.0.0.1:${MAINLAND_SOCKS_PORT}) [recommended for x-ui chaining]"
    echo "2) Public bind (0.0.0.0:${MAINLAND_SOCKS_PORT})"
    echo "3) Custom bind address (ip:port)"
    read -r -p "Choose bind mode (or press enter for [1]): " bind_choice
    [ -z "${bind_choice}" ] && bind_choice=1
    case "${bind_choice}" in
        1) MAINLAND_SOCKS_ADDRESS="127.0.0.1:${MAINLAND_SOCKS_PORT}" ;;
        2) MAINLAND_SOCKS_ADDRESS="0.0.0.0:${MAINLAND_SOCKS_PORT}" ;;
        3)
            read -r -p "Enter SOCKS bind address (ip:port): " MAINLAND_SOCKS_ADDRESS
            if [[ -z "${MAINLAND_SOCKS_ADDRESS}" ]]; then
                echo "Error: SOCKS bind address is required"
                exit 1
            fi
            ;;
        *)
            echo "Error: Invalid bind mode"
            exit 1
            ;;
    esac

    read -r -p "SOCKS username (default [relay]): " MAINLAND_SOCKS_USERNAME
    [ -z "${MAINLAND_SOCKS_USERNAME}" ] && MAINLAND_SOCKS_USERNAME="relay"

    default_password=$(generate_random_password)
    read -r -p "SOCKS password (default random [${default_password}]): " MAINLAND_SOCKS_PASSWORD
    if [[ -z "${MAINLAND_SOCKS_PASSWORD}" ]]; then
        MAINLAND_SOCKS_PASSWORD="${default_password}"
    fi

    return 0
}

configure_mainland_client_files() {
    local temp_file=""

    if ! cd "${CLIENT_INSTALL_DIR}" 2>/dev/null; then
        echo "Error: Cannot access client install directory: ${CLIENT_INSTALL_DIR}"
        exit 1
    fi

    if [[ ! -x "./setup_wizard" ]]; then
        echo "Error: setup_wizard not found or not executable in ${CLIENT_INSTALL_DIR}"
        echo "The TrustTunnel Client may not have been installed correctly."
        exit 1
    fi

    echo "Configuring TrustTunnel Client..."
    if ! ./setup_wizard --mode non-interactive --endpoint_config "${ENDPOINT_CONFIG_SOURCE_FILE}" --settings "${CLIENT_CONFIG_FILE}" 2>&1; then
        echo ""
        echo "Error: setup_wizard failed to configure client."
        echo "Endpoint config file: ${ENDPOINT_CONFIG_SOURCE_FILE}"
        echo "Please verify the endpoint configuration is valid."
        exit 1
    fi

    sed -i 's/^listener = .*/listener = "socks"/' "${CLIENT_CONFIG_FILE}"
    sed -i "s/^upstream_protocol = .*/upstream_protocol = \"${MAINLAND_UPSTREAM_PROTOCOL}\"/" "${CLIENT_CONFIG_FILE}"
    sed -i "s/^upstream_fallback_protocol = .*/upstream_fallback_protocol = \"${MAINLAND_UPSTREAM_FALLBACK}\"/" "${CLIENT_CONFIG_FILE}"
    sed -i "s/^anti_dpi = .*/anti_dpi = ${MAINLAND_ANTI_DPI}/" "${CLIENT_CONFIG_FILE}"

    temp_file=$(mktemp)
    awk '
        BEGIN { skip = 0 }

        # Remove every listener section (e.g. [listener], [listener.tun], [listener.http], [listener.socks]).
        /^\[[[:space:]]*listener([.][^]]+)?[[:space:]]*\]$/ {
            skip = 1
            next
        }

        # Exit skip mode when a non-listener section starts.
        skip && /^\[/ {
            if ($0 !~ /^\[[[:space:]]*listener([.][^]]+)?[[:space:]]*\]$/) {
                skip = 0
            }
        }

        !skip { print }
    ' "${CLIENT_CONFIG_FILE}" > "${temp_file}"
    mv "${temp_file}" "${CLIENT_CONFIG_FILE}"

    cat >> "${CLIENT_CONFIG_FILE}" << EOF

[listener.socks]
address = "${MAINLAND_SOCKS_ADDRESS}"
username = "${MAINLAND_SOCKS_USERNAME}"
password = "${MAINLAND_SOCKS_PASSWORD}"
EOF

    # Safety check: only one listener section should remain.
    if [[ "$(grep -Ec '^\[[[:space:]]*listener([.][^]]+)?[[:space:]]*\]$' "${CLIENT_CONFIG_FILE}")" -ne 1 ]]; then
        echo "Error: Invalid client listener configuration generated"
        return 1
    fi

    chmod 600 "${CLIENT_CONFIG_FILE}"
}

create_mainland_client_marker() {
    cat > "${CLIENT_MARKER_FILE}" << EOF
ROLE=tunnel-mainland
CREATED_AT=$(date -Iseconds)
ENDPOINT_SOURCE=${MAINLAND_SOURCE_TYPE}
ENDPOINT_CONFIG_FILE=${ENDPOINT_CONFIG_SOURCE_FILE}
SOCKS_ADDRESS=${MAINLAND_SOCKS_ADDRESS}
SOCKS_USERNAME=${MAINLAND_SOCKS_USERNAME}
UPSTREAM_PROTOCOL=${MAINLAND_UPSTREAM_PROTOCOL}
UPSTREAM_FALLBACK=${MAINLAND_UPSTREAM_FALLBACK}
ANTI_DPI=${MAINLAND_ANTI_DPI}
EOF
    chmod 600 "${CLIENT_MARKER_FILE}"
}

show_current_configuration() {
    local listen_address=""
    local listen_port=""
    local public_address=""
    local cert_type=""
    local domain_name=""
    local ipv6_enabled=""
    local allow_private_network=""
    local vpn_username=""
    local vpn_password=""
    local protocols=""
    local forward_mode="direct"
    local socks5_address=""
    local endpoint=""

    if [[ -f "${CONFIG_DIR}/vpn.toml" ]]; then
        listen_address=$(sed -n 's/^[[:space:]]*listen_address[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${CONFIG_DIR}/vpn.toml" | head -n1)
        ipv6_enabled=$(sed -n 's/^[[:space:]]*ipv6_available[[:space:]]*=[[:space:]]*\(true\|false\).*/\1/p' "${CONFIG_DIR}/vpn.toml" | head -n1)
        allow_private_network=$(sed -n 's/^[[:space:]]*allow_private_network_connections[[:space:]]*=[[:space:]]*\(true\|false\).*/\1/p' "${CONFIG_DIR}/vpn.toml" | head -n1)

        if grep -q '^\[listen_protocols\.http1\]' "${CONFIG_DIR}/vpn.toml"; then
            protocols="HTTP/1.1"
        fi
        if grep -q '^\[listen_protocols\.http2\]' "${CONFIG_DIR}/vpn.toml"; then
            if [[ -n "${protocols}" ]]; then
                protocols="${protocols}, HTTP/2"
            else
                protocols="HTTP/2"
            fi
        fi
        if grep -q '^\[listen_protocols\.quic\]' "${CONFIG_DIR}/vpn.toml"; then
            if [[ -n "${protocols}" ]]; then
                protocols="${protocols}, QUIC/HTTP3"
            else
                protocols="QUIC/HTTP3"
            fi
        fi

        if grep -q '^\[forward_protocol\.socks5\]' "${CONFIG_DIR}/vpn.toml"; then
            forward_mode="socks5"
            socks5_address=$(awk '
                /^\[forward_protocol\.socks5\]$/ { section = 1; next }
                section && /^\[/ { section = 0 }
                section && /^[[:space:]]*address[[:space:]]*=/ {
                    gsub(/^[[:space:]]*address[[:space:]]*=[[:space:]]*"/, "", $0)
                    gsub(/".*$/, "", $0)
                    print
                    exit
                }
            ' "${CONFIG_DIR}/vpn.toml")
        fi

    fi

    if [[ -n "${listen_address}" ]]; then
        listen_port="${listen_address##*:}"
    fi

    if [[ -f "${CONFIG_DIR}/hosts.toml" ]]; then
        domain_name=$(sed -n 's/^[[:space:]]*hostname[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${CONFIG_DIR}/hosts.toml" | head -n1)
    fi

    if [[ -f "${CONFIG_DIR}/credentials.toml" ]]; then
        vpn_username=$(sed -n 's/^[[:space:]]*username[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${CONFIG_DIR}/credentials.toml" | head -n1)
        vpn_password=$(sed -n 's/^[[:space:]]*password[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${CONFIG_DIR}/credentials.toml" | head -n1)
    fi

    if [[ -f "${MARKER_FILE}" ]]; then
        # shellcheck source=/dev/null
        source "${MARKER_FILE}"
        public_address="${PUBLIC_ADDRESS:-}"
        cert_type="${CERT_TYPE:-}"
        [[ -z "${domain_name}" ]] && domain_name="${DOMAIN_NAME:-}"
        [[ -z "${listen_port}" ]] && listen_port="${LISTEN_PORT:-}"
        [[ -z "${allow_private_network}" ]] && allow_private_network="${ALLOW_PRIVATE_NETWORK:-}"
        [[ "${forward_mode}" == "direct" && -n "${FORWARD_MODE:-}" ]] && forward_mode="${FORWARD_MODE}"
        [[ -z "${socks5_address}" ]] && socks5_address="${SOCKS5_ADDRESS:-}"
    fi

    if [[ -n "${public_address}" && -n "${listen_port}" ]]; then
        endpoint="${public_address}:${listen_port}"
    fi

    echo ""
    echo "Current Configuration"
    echo ""
    echo "  Endpoint       : ${endpoint:-N/A}"
    echo "  Public Address : ${public_address:-N/A}"
    echo "  Listen Address : ${listen_address:-N/A}"
    echo "  Port           : ${listen_port:-N/A}"
    echo "  Domain         : ${domain_name:-N/A}"
    echo "  Certificate    : ${cert_type:-N/A}"
    echo "  IPv6 Routing   : ${ipv6_enabled:-N/A}"
    echo "  Protocols      : ${protocols:-N/A}"
    echo "  Forward Mode   : ${forward_mode:-N/A}"
    if [[ "${forward_mode}" == "socks5" ]]; then
        echo "  SOCKS5 Address : ${socks5_address:-N/A}"
    fi
    echo "  Private Access : ${allow_private_network:-N/A}"
    echo "  Username       : ${vpn_username:-N/A}"
    echo "  Password       : ${vpn_password:-N/A}"
}

show_mainland_current_configuration() {
    local endpoint_hostname=""
    local endpoint_addresses=""
    local upstream_protocol=""
    local upstream_fallback=""
    local anti_dpi=""
    local socks_address=""
    local socks_username=""
    local socks_password=""

    if [[ ! -f "${CLIENT_CONFIG_FILE}" ]]; then
        echo "Error: Mainland client config not found"
        return
    fi

    endpoint_hostname=$(awk '
        /^\[endpoint\]$/ { section = 1; next }
        section && /^\[/ { section = 0 }
        section && /^[[:space:]]*hostname[[:space:]]*=/ {
            gsub(/^[[:space:]]*hostname[[:space:]]*=[[:space:]]*"/, "", $0)
            gsub(/".*$/, "", $0)
            print
            exit
        }
    ' "${CLIENT_CONFIG_FILE}")
    endpoint_addresses=$(awk '
        /^\[endpoint\]$/ { section = 1; next }
        section && /^\[/ { section = 0 }
        section && /^[[:space:]]*addresses[[:space:]]*=/ {
            sub(/^[[:space:]]*addresses[[:space:]]*=[[:space:]]*/, "", $0)
            print
            exit
        }
    ' "${CLIENT_CONFIG_FILE}")
    upstream_protocol=$(awk '
        /^\[endpoint\]$/ { section = 1; next }
        section && /^\[/ { section = 0 }
        section && /^[[:space:]]*upstream_protocol[[:space:]]*=/ {
            gsub(/^[[:space:]]*upstream_protocol[[:space:]]*=[[:space:]]*"/, "", $0)
            gsub(/".*$/, "", $0)
            print
            exit
        }
    ' "${CLIENT_CONFIG_FILE}")
    upstream_fallback=$(awk '
        /^\[endpoint\]$/ { section = 1; next }
        section && /^\[/ { section = 0 }
        section && /^[[:space:]]*upstream_fallback_protocol[[:space:]]*=/ {
            gsub(/^[[:space:]]*upstream_fallback_protocol[[:space:]]*=[[:space:]]*"/, "", $0)
            gsub(/".*$/, "", $0)
            print
            exit
        }
    ' "${CLIENT_CONFIG_FILE}")
    anti_dpi=$(awk '
        /^\[endpoint\]$/ { section = 1; next }
        section && /^\[/ { section = 0 }
        section && /^[[:space:]]*anti_dpi[[:space:]]*=/ {
            gsub(/^[[:space:]]*anti_dpi[[:space:]]*=[[:space:]]*/, "", $0)
            print
            exit
        }
    ' "${CLIENT_CONFIG_FILE}")
    socks_address=$(awk '
        /^\[listener\.socks\]$/ { section = 1; next }
        section && /^\[/ { section = 0 }
        section && /^[[:space:]]*address[[:space:]]*=/ {
            gsub(/^[[:space:]]*address[[:space:]]*=[[:space:]]*"/, "", $0)
            gsub(/".*$/, "", $0)
            print
            exit
        }
    ' "${CLIENT_CONFIG_FILE}")
    socks_username=$(awk '
        /^\[listener\.socks\]$/ { section = 1; next }
        section && /^\[/ { section = 0 }
        section && /^[[:space:]]*username[[:space:]]*=/ {
            gsub(/^[[:space:]]*username[[:space:]]*=[[:space:]]*"/, "", $0)
            gsub(/".*$/, "", $0)
            print
            exit
        }
    ' "${CLIENT_CONFIG_FILE}")
    socks_password=$(awk '
        /^\[listener\.socks\]$/ { section = 1; next }
        section && /^\[/ { section = 0 }
        section && /^[[:space:]]*password[[:space:]]*=/ {
            gsub(/^[[:space:]]*password[[:space:]]*=[[:space:]]*"/, "", $0)
            gsub(/".*$/, "", $0)
            print
            exit
        }
    ' "${CLIENT_CONFIG_FILE}")

    echo ""
    echo "Mainland Relay Configuration"
    echo ""
    echo "  Endpoint Host   : ${endpoint_hostname:-N/A}"
    echo "  Endpoint Addr   : ${endpoint_addresses:-N/A}"
    echo "  Upstream Proto  : ${upstream_protocol:-N/A}"
    echo "  Fallback Proto  : ${upstream_fallback:-none}"
    echo "  Anti-DPI        : ${anti_dpi:-N/A}"
    echo "  SOCKS Address   : ${socks_address:-N/A}"
    echo "  SOCKS Username  : ${socks_username:-N/A}"
    echo "  SOCKS Password  : ${socks_password:-N/A}"
}

# ============================================================================
# Menu Functions
# ============================================================================

show_status() {
    echo ""
    echo "TrustTunnel Status"
    echo ""
    
    # Installation status
    if is_installed; then
        echo "TrustTunnel is installed at ${INSTALL_DIR}"
    else
        echo "TrustTunnel is not installed"
        return
    fi
    
    # Configuration status
    if is_configured; then
        echo "TrustTunnel is configured"
        # shellcheck source=/dev/null
        source "${MARKER_FILE}"
        echo "  Public Address: ${PUBLIC_ADDRESS}"
        echo "  Username:       ${VPN_USERNAME}"
    else
        echo "TrustTunnel is not configured"
    fi
    
    # Service status
    if is_service_running; then
        echo "Service is running"
    else
        echo "Service is not running"
    fi
    
    if is_service_enabled; then
        echo "Service is enabled (auto-start on boot)"
    else
        echo "Service is not enabled"
    fi
}

menu_start_service() {
    if is_service_running; then
        echo "Service is already running"
    else
        start_service
    fi
}

menu_stop_service() {
    stop_service
}

menu_restart_service() {
    echo "Restarting TrustTunnel service..."
    systemctl restart ${SERVICE_NAME}
    sleep 2
    if is_service_running; then
        echo "Service restarted successfully"
    else
        echo "Error: Failed to restart service"
    fi
}

menu_view_logs() {
    echo ""
    echo "Service Logs (Ctrl+C to exit)"
    echo ""
    journalctl -u ${SERVICE_NAME} -f
}

menu_edit_config() {
    echo ""
    echo "Edit Configuration"
    echo ""
    echo "Which configuration file would you like to edit?"
    echo ""
    echo "1) vpn.toml         - Main endpoint settings"
    echo ""
    echo "2) hosts.toml       - TLS/Certificate settings"
    echo ""
    echo "3) credentials.toml - User credentials"
    echo ""
    echo "4) rules.toml       - Connection filtering rules"
    echo ""
    echo "5) Cancel"
    echo ""
    read -r -p "Enter your choice: " choice
    
    local file=""
    case "$choice" in
        1) file="${CONFIG_DIR}/vpn.toml" ;;
        2) file="${CONFIG_DIR}/hosts.toml" ;;
        3) file="${CONFIG_DIR}/credentials.toml" ;;
        4) file="${CONFIG_DIR}/rules.toml" ;;
        5) return ;;
        *) echo "Invalid choice"; return ;;
    esac
    
    if [[ -f "$file" ]]; then
        ${EDITOR:-nano} "$file"
        echo "Remember to restart the service for changes to take effect"
    else
        echo "Error: File not found: $file"
    fi
}

menu_add_user() {
    echo ""
    echo "Add New User"
    echo ""
    
    read -r -p "Enter new username: " new_username
    if [[ -z "$new_username" ]]; then
        echo "Error: Username cannot be empty"
        return
    fi
    
    local default_pass
    default_pass=$(generate_random_password)
    echo ""
    read -r -p "Enter password (or press enter for random [$default_pass]): " new_password
    [ -z "$new_password" ] && new_password="$default_pass"
    
    # Append to credentials file
    {
        echo ""
        echo "[[client]]"
        echo "username = \"${new_username}\""
        echo "password = \"${new_password}\""
    } >> "${CONFIG_DIR}/credentials.toml"
    
    echo ""
    echo "User '${new_username}' added"
    echo "Password: ${new_password}"
    echo "Restart the service for changes to take effect"
}

menu_show_client_config() {
    show_client_config
}

menu_generate_bundle_token() {
    if generate_mainland_bundle_token; then
        echo "Bundle token generated successfully"
    else
        echo "Failed to generate bundle token"
    fi
}

menu_reinstall() {
    echo ""
    echo "Reinstall TrustTunnel"
    echo ""
    echo "This will reinstall TrustTunnel but keep your configuration files"
    echo ""
    read -r -p "Are you sure? [y/N]: " confirm
    confirm=$(echo "${confirm:-n}" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$confirm" == "y" ]]; then
        stop_service
        
        # Backup config files
        local backup_dir="/tmp/trusttunnel_backup_$$"
        mkdir -p "$backup_dir"
        cp "${CONFIG_DIR}"/*.toml "$backup_dir/" 2>/dev/null || true
        cp -r "${CONFIG_DIR}/certs" "$backup_dir/" 2>/dev/null || true
        cp "${MARKER_FILE}" "$backup_dir/" 2>/dev/null || true
        
        # Reinstall
        install_trusttunnel
        
        # Restore config files
        cp "$backup_dir"/*.toml "${CONFIG_DIR}/" 2>/dev/null || true
        cp -r "$backup_dir/certs" "${CONFIG_DIR}/" 2>/dev/null || true
        cp "$backup_dir/.trusttunnel_configured" "${MARKER_FILE}" 2>/dev/null || true
        rm -rf "$backup_dir"
        
        start_service
        echo "Reinstallation complete"
    else
        echo "Reinstallation cancelled"
    fi
}

menu_uninstall() {
    echo ""
    echo "Uninstall TrustTunnel"
    echo ""
    echo "This will completely remove TrustTunnel and all configuration!"
    echo ""
    read -r -p "Are you sure? [y/N]: " confirm
    confirm=$(echo "${confirm:-n}" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$confirm" == "y" ]]; then
        echo "Stopping service..."
        stop_service
        
        echo "Disabling service..."
        systemctl disable ${SERVICE_NAME} 2>/dev/null || true
        
        echo "Removing service file..."
        rm -f "${SERVICE_FILE}"
        systemctl daemon-reload
        
        echo "Removing installation directory..."
        rm -rf "${INSTALL_DIR}"
        rm -f "${BUNDLE_FILE}"
        clear_installer_mode
        
        echo "TrustTunnel has been completely uninstalled"
        exit 0
    else
        echo "Uninstallation cancelled"
    fi
}

show_menu() {
    while true; do
        echo ""
        echo "TrustTunnel Management Menu"
        echo ""
        
        # Quick status
        if is_service_running; then
            echo "Status: Running"
        else
            echo "Status: Stopped"
        fi
        echo ""
        
        echo "Choose an option:"
        echo ""
        echo "1) Start Service"
        echo ""
        echo "2) Stop Service"
        echo ""
        echo "3) Restart Service"
        echo ""
        echo "4) View Logs"
        echo ""
        echo "5) Show Status"
        echo ""
        echo "6) Edit Configuration"
        echo ""
        echo "7) Add User"
        echo ""
        echo "8) Show Client Config"
        echo ""
        echo "9) Reinstall TrustTunnel"
        echo ""
        echo "10) Uninstall TrustTunnel"
        echo ""
        echo "11) Generate Mainland Bundle Token"
        echo ""
        echo "0) Exit"
        echo ""
        
        read -r -p "Enter your choice: " choice
        
        case "$choice" in
            1) menu_start_service ;;
            2) menu_stop_service ;;
            3) menu_restart_service ;;
            4) menu_view_logs ;;
            5) show_status ;;
            6) menu_edit_config ;;
            7) menu_add_user ;;
            8) menu_show_client_config ;;
            9) menu_reinstall ;;
            10) menu_uninstall ;;
            11) menu_generate_bundle_token ;;
            0) 
                echo "Goodbye!"
                exit 0 
                ;;
            *) echo "Invalid option" ;;
        esac
        
        echo ""
        read -r -p "Press Enter to continue..."
    done
}

show_mainland_status() {
    echo ""
    echo "Mainland Relay Status"
    echo ""

    if is_client_installed; then
        echo "TrustTunnel Client installed at ${CLIENT_INSTALL_DIR}"
    else
        echo "TrustTunnel Client is not installed"
        return
    fi

    if is_client_configured; then
        echo "TrustTunnel Client is configured"
    else
        echo "TrustTunnel Client is not configured"
    fi

    if is_client_service_running; then
        echo "Client service is running"
    else
        echo "Client service is not running"
    fi

    if is_client_service_enabled; then
        echo "Client service is enabled (auto-start on boot)"
    else
        echo "Client service is not enabled"
    fi
}

menu_mainland_start_service() {
    if is_client_service_running; then
        echo "Client service is already running"
    else
        start_client_service
    fi
}

menu_mainland_stop_service() {
    stop_client_service
}

menu_mainland_restart_service() {
    echo "Restarting TrustTunnel Client service..."
    systemctl restart ${CLIENT_SERVICE_NAME}
    sleep 2
    if is_client_service_running; then
        echo "Client service restarted successfully"
    else
        echo "Error: Failed to restart client service"
    fi
}

menu_mainland_view_logs() {
    echo ""
    echo "TrustTunnel Client Logs (Ctrl+C to exit)"
    echo ""
    journalctl -u ${CLIENT_SERVICE_NAME} -f
}

menu_mainland_edit_config() {
    if [[ -f "${CLIENT_CONFIG_FILE}" ]]; then
        ${EDITOR:-nano} "${CLIENT_CONFIG_FILE}"
        echo "Remember to restart the client service for changes to take effect"
    else
        echo "Error: Client config not found: ${CLIENT_CONFIG_FILE}"
    fi
}

menu_mainland_uninstall() {
    echo ""
    echo "Uninstall Mainland Relay"
    echo ""
    echo "This will remove TrustTunnel Client relay and configuration from this host."
    echo ""
    read -r -p "Are you sure? [y/N]: " confirm
    confirm=$(echo "${confirm:-n}" | tr '[:upper:]' '[:lower:]')

    if [[ "$confirm" == "y" ]]; then
        stop_client_service
        systemctl disable ${CLIENT_SERVICE_NAME} 2>/dev/null || true
        rm -f "${CLIENT_SERVICE_FILE}"
        systemctl daemon-reload
        rm -rf "${CLIENT_INSTALL_DIR}"
        clear_installer_mode
        echo "Mainland relay uninstalled"
        exit 0
    else
        echo "Uninstallation cancelled"
    fi
}

show_mainland_menu() {
    while true; do
        echo ""
        echo "TrustTunnel Mainland Relay Menu"
        echo ""

        if is_client_service_running; then
            echo "Status: Running"
        else
            echo "Status: Stopped"
        fi
        echo ""
        echo "Choose an option:"
        echo ""
        echo "1) Start Client Service"
        echo ""
        echo "2) Stop Client Service"
        echo ""
        echo "3) Restart Client Service"
        echo ""
        echo "4) View Client Logs"
        echo ""
        echo "5) Show Relay Status"
        echo ""
        echo "6) Show Relay Configuration"
        echo ""
        echo "7) Edit Client Configuration"
        echo ""
        echo "8) Uninstall Mainland Relay"
        echo ""
        echo "0) Exit"
        echo ""

        read -r -p "Enter your choice: " choice

        case "$choice" in
            1) menu_mainland_start_service ;;
            2) menu_mainland_stop_service ;;
            3) menu_mainland_restart_service ;;
            4) menu_mainland_view_logs ;;
            5) show_mainland_status ;;
            6) show_mainland_current_configuration ;;
            7) menu_mainland_edit_config ;;
            8) menu_mainland_uninstall ;;
            0)
                echo "Goodbye!"
                exit 0
                ;;
            *) echo "Invalid option" ;;
        esac

        echo ""
        read -r -p "Press Enter to continue..."
    done
}

# ============================================================================
# First-Time Installation Flow
# ============================================================================

first_time_install() {
    echo ""
    echo "First-Time Installation"
    echo ""
    
    # Check architecture
    local arch
    arch=$(get_arch)
    if [[ "$arch" == "unsupported" ]]; then
        echo "Error: Unsupported architecture: $(uname -m)"
        echo "TrustTunnel supports x86_64 and aarch64 architectures"
        exit 1
    fi
    
    echo "Welcome to TrustTunnel VPN Manager!"
    echo "This wizard will guide you through the installation process."
    echo ""
    
    # Install TrustTunnel
    install_trusttunnel
    
    # Collect configuration from user
    collect_configuration
    
    # Create configuration files
    create_configuration_files
    
    # Setup systemd service
    setup_systemd_service
    
    # Start service (if not Let's Encrypt - needs manual setup)
    if [[ "$CERT_TYPE" != "letsencrypt" ]]; then
        start_service
    else
        echo "Please complete Let's Encrypt setup before starting the service"
        echo "Run: cd ${INSTALL_DIR} && sudo ./setup_wizard"
    fi
    
    # Show current endpoint settings
    show_current_configuration

    # Show client configuration
    if [[ "$CERT_TYPE" != "letsencrypt" ]]; then
        show_client_config
    fi
    
    echo ""
    echo "Installation Complete!"
    echo ""
    echo "TrustTunnel VPN has been installed and configured"
    echo ""
    echo "Run this script again to access the management menu"
    echo "  - bash ${MANAGER_SCRIPT}"
    echo ""
    echo "Useful commands:"
    echo "  - View logs:      journalctl -u ${SERVICE_NAME} -f"
    echo "  - Restart:        systemctl restart ${SERVICE_NAME}"
    echo "  - Stop:           systemctl stop ${SERVICE_NAME}"
    echo ""
    
    if [[ "$CERT_TYPE" == "selfsigned" ]]; then
        echo "Note: Self-signed certificates only work with CLI client"
        echo "Flutter Client requires a valid CA-signed certificate"
    fi
}

first_time_standalone_install() {
    first_time_install
    set_installer_mode "standalone"
}

first_time_tunnel_foreign_install() {
    first_time_install
    set_installer_mode "tunnel-foreign"
    echo ""
    echo "Generating mainland relay bundle token..."
    generate_mainland_bundle_token || true
}

first_time_tunnel_mainland_install() {
    echo ""
    echo "Tunnel Mode: Mainland Relay Client"
    echo ""

    install_trusttunnel_client
    collect_mainland_client_configuration
    echo "Applying mainland client configuration..."
    configure_mainland_client_files
    create_mainland_client_marker
    setup_client_systemd_service
    start_client_service
    show_mainland_current_configuration
    set_installer_mode "tunnel-mainland"

    echo ""
    echo "Mainland relay setup complete."
    echo "Run this script again for mainland relay management:"
    echo "  - bash ${MANAGER_SCRIPT}"
}

first_time_setup_flow() {
    local install_choice=""
    local tunnel_role=""

    echo ""
    echo "Installation Mode"
    echo ""
    echo "1) Standalone VPN Service (default)"
    echo "2) Tunnel Mode"
    echo ""
    read -r -p "Choose installation mode (or press enter for [1]): " install_choice
    [ -z "${install_choice}" ] && install_choice=1

    case "${install_choice}" in
        1)
            if is_client_installed || is_client_configured; then
                echo "Error: This host already has mainland relay role."
                echo "One role per host is enforced."
                exit 1
            fi
            first_time_standalone_install
            ;;
        2)
            echo ""
            echo "Tunnel Role (one role per host)"
            echo "1) Foreign Exit Server (endpoint)"
            echo "2) Mainland Relay Client (socks)"
            echo ""
            read -r -p "Choose tunnel role: " tunnel_role
            case "${tunnel_role}" in
                1)
                    if is_client_installed || is_client_configured; then
                        echo "Error: This host already has mainland relay role."
                        echo "One role per host is enforced."
                        exit 1
                    fi
                    first_time_tunnel_foreign_install
                    ;;
                2)
                    if is_installed || is_configured; then
                        echo "Error: This host already has endpoint role."
                        echo "One role per host is enforced."
                        exit 1
                    fi
                    first_time_tunnel_mainland_install
                    ;;
                *)
                    echo "Error: Invalid tunnel role"
                    exit 1
                    ;;
            esac
            ;;
        *)
            echo "Error: Invalid installation mode"
            exit 1
            ;;
    esac
}

# ============================================================================
# Main Entry Point
# ============================================================================

main() {
    # Introduction animation
    echo ""
    echo ""
    print_with_delay "trusttunnel-installer by DEATHLINE | @NamelesGhoul" 0.1
    echo ""
    echo ""
    
    check_root
    check_os
    install_management_script

    local mode
    mode=$(get_installer_mode)

    case "${mode}" in
        "standalone")
            if is_client_installed || is_client_configured; then
                echo "Error: Mainland relay role detected on this host."
                echo "One role per host is enforced."
                exit 1
            fi

            if is_installed && is_configured; then
                show_menu
            else
                first_time_standalone_install
            fi
            ;;
        "tunnel-foreign")
            if is_client_installed || is_client_configured; then
                echo "Error: Mainland relay role detected on this host."
                echo "One role per host is enforced."
                exit 1
            fi

            if is_installed && is_configured; then
                show_menu
            else
                first_time_tunnel_foreign_install
            fi
            ;;
        "tunnel-mainland")
            if is_installed || is_configured; then
                echo "Error: Endpoint role detected on this host."
                echo "One role per host is enforced."
                exit 1
            fi

            if is_client_installed && is_client_configured; then
                show_mainland_menu
            else
                first_time_tunnel_mainland_install
            fi
            ;;
        "")
            first_time_setup_flow
            ;;
        *)
            echo "Warning: Unknown installer mode '${mode}' detected. Resetting mode selection."
            clear_installer_mode
            first_time_setup_flow
            ;;
    esac
}

# Run main function
main "$@"
