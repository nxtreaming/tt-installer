# TrustTunnel VPN Installer

TrustTunnel VPN Installer allows users to effortlessly set up the TrustTunnel VPN service. Use a simple command to initiate a secure and fast VPN connection on your system.

## Features

- 🚀 Quick installation using a single command
- 🔒 Secure connection setup with TLS certificates
- 🖥️ Supports multiple platforms (x86_64, aarch64)
- 🔧 Built-in management menu for easy administration
- 👥 Multi-user support
- ⚙️ Advanced endpoint options (HTTP/1.1, HTTP/2, QUIC, SOCKS5 forwarding)
- 🌉 Tunnel mode with one-role-per-host (foreign endpoint or mainland relay client)
- 🔑 Bundle token export/import for fast foreign->mainland pairing

## Prerequisites

- Supported Operating Systems: Linux
- `curl` must be installed on your system
- Internet connection
- Root privileges

## Installation

1. **Download and Run the Installer Script**

   ```bash
   bash <(curl -fsSL https://raw.githubusercontent.com/deathline94/tt-installer/main/installer.sh)
   ```

## Usage

On first run, choose one deployment mode:

- **Standalone VPN Service** - regular endpoint installation
- **Tunnel Mode** - choose one role per host:
  - **Foreign Exit Server** (endpoint)
  - **Mainland Relay Client** (TrustTunnel Client with authenticated SOCKS5)

After installation, a reusable manager script is created under `/root`.
Run this command again to access the management menu:

```bash
bash /root/tt-installer.sh
```

### Management Options

- Start/Stop/Restart Service
- View Logs
- Edit Configuration
- Add Users
- Show Client Config
- Reinstall/Uninstall

## Certificate Options

The installer supports three certificate options:

| Option | Works With | Notes |
|--------|------------|-------|
| **Self-signed** | CLI Client only | Quick setup for testing, does not work with Flutter Client |
| **Let's Encrypt** | All clients | Requires a valid domain pointing to your server |
| **Existing certificate** | All clients | Use your own CA-signed certificate |

> ⚠️ **Note:** Self-signed certificates only work with the TrustTunnel CLI client. The Flutter Client requires a valid CA-signed certificate (Let's Encrypt or your own).
>
> In **Tunnel Mode**, set a **TLS hostname** that is domain-like (for example `vpn.example.com` or `tt.local`), not a raw IP.  
> The relay can still connect to an IP address via endpoint `addresses`, but TLS hostname/SNI should be a hostname.
>
> For **Existing certificate** mode, the installer auto-scans common paths and shows valid choices by domain:
> `/etc/letsencrypt/live/*`, `/root/.acme.sh/*`, `/root/cert/*`, common web server SSL folders, and `/etc/ssl/{certs,private}`.

## Credits

This installer is built for [TrustTunnel](https://github.com/TrustTunnel/TrustTunnel) - a secure VPN solution that provides encrypted tunneling for your network traffic.
