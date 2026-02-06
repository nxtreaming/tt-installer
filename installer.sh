#!/bin/bash

# ============================================================================
# TrustTunnel VPN Manager
# A comprehensive installation and management script for TrustTunnel VPN
# ============================================================================

set -e

# Configuration
INSTALL_DIR="/opt/trusttunnel"
CONFIG_DIR="${INSTALL_DIR}"
SERVICE_NAME="trusttunnel"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
MARKER_FILE="${INSTALL_DIR}/.trusttunnel_configured"

# Function to print characters with delay
print_with_delay() {
    text="$1"
    delay="$2"
    for ((i = 0; i < ${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
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
            if [[ -z "$DOMAIN_NAME" ]]; then
                echo "Error: Domain name is required for Let's Encrypt"
                exit 1
            fi
            read -r -p "Enter email for Let's Encrypt notifications: " LE_EMAIL
            export LE_EMAIL
            ;;
        2)
            CERT_TYPE="selfsigned"
            DOMAIN_NAME="${PUBLIC_ADDRESS}"
            ;;
        3)
            CERT_TYPE="existing"
            echo ""
            read -r -p "Enter path to certificate chain (cert.pem): " CERT_PATH
            read -r -p "Enter path to private key (key.pem): " KEY_PATH
            if [[ ! -f "$CERT_PATH" ]] || [[ ! -f "$KEY_PATH" ]]; then
                echo "Error: Certificate files not found"
                exit 1
            fi
            DOMAIN_NAME="${PUBLIC_ADDRESS}"
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
allow_private_network_connections = false

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

[listen_protocols.http1]
upload_buffer_size = 32768

[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 131072
max_concurrent_streams = 1000
max_frame_size = 16384
header_table_size = 65536

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

# Forward protocol
[forward_protocol]
direct = {}
EOF
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
    systemctl daemon-reload
    echo "Systemd daemon reloaded"
    
    # Enable service
    systemctl enable ${SERVICE_NAME} > /dev/null 2>&1
    echo "Service enabled to start on boot"
}

start_service() {
    echo "Starting TrustTunnel service..."
    systemctl start ${SERVICE_NAME}
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
        read -r -p "Type 'UNINSTALL' to confirm: " confirm2
        if [[ "$confirm2" == "UNINSTALL" ]]; then
            echo "Stopping service..."
            stop_service
            
            echo "Disabling service..."
            systemctl disable ${SERVICE_NAME} 2>/dev/null || true
            
            echo "Removing service file..."
            rm -f "${SERVICE_FILE}"
            systemctl daemon-reload
            
            echo "Removing installation directory..."
            rm -rf "${INSTALL_DIR}"
            
            echo "TrustTunnel has been completely uninstalled"
            exit 0
        else
            echo "Uninstallation cancelled"
        fi
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

# ============================================================================
# Main Entry Point
# ============================================================================

main() {
    # Introduction animation
    echo ""
    echo ""
    print_with_delay "trusttunnel-installer by DEATHLINE | @NamelesGhoul" 0.05
    echo ""
    echo ""
    
    check_root
    check_os
    
    if is_installed && is_configured; then
        # Already installed - show management menu
        show_menu
    else
        # First time - run installation wizard
        first_time_install
    fi
}

# Run main function
main "$@"
