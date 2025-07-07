# Odoo 17 Automated Installer

Welcome! This project provides an easy, reliable, and production-ready way to install Odoo 17 on your own server. Whether you're a business owner, developer, or sysadmin, this script helps you get Odoo up and running quickly, securely, and with best practices by default.

---

## System Requirements & Monitoring Access

**Supported Distributions:**
- Debian 12 (Bookworm) and Ubuntu 24.04 LTS (Noble Numbat) are fully supported.
- Alpine Linux support for containerized environments (experimental).
- Basic support for RHEL/CentOS/Fedora and Arch Linux distributions.
- The script is designed for modern Debian-based distributions. Other Debian-based distros (like Ubuntu 22.04, Linux Mint, etc.) may work, but only Debian 12+ and Ubuntu 24.04+ are officially tested and recommended.

**Recommended System:**
- 4+ CPU cores (8+ recommended)
- 16GB RAM minimum (64GB recommended)
- 50GB+ SSD storage
- Root access
- A valid domain name

**Monitoring URLs & Ports:**
- **Odoo:**         `https://your-domain` (port 443)
- **Grafana:**      `http://your-domain:3000` (port 3000)
- **Netdata:**      `http://your-domain:19999` (port 19999)
- **Prometheus:**   `http://your-domain:9090` (port 9090)
- **Alertmanager:** `http://your-domain:9093` (port 9093)

> All monitoring dashboards are protected by authentication and/or firewall rules by default. Please change default passwords after installation.

---

## Table of Contents

1. [Installation Guide](#installation-guide)
   - [Domain Configuration](#domain-configuration)
   - [Server Installation](#server-installation)
   - [Initial Setup](#initial-setup)
   - [Advanced Options](#advanced-options)

2. [Access and Usage](#access-and-usage)
   - [First Launch](#first-launch)
   - [User Management](#user-management)
   - [Initial Configuration](#initial-configuration)

3. [Monitoring and Supervision](#monitoring-and-supervision)
   - [Dashboards](#dashboards)
   - [Alert System](#alert-system)
   - [Log Management](#log-management)

4. [E-commerce and Website](#e-commerce-and-website)
   - [Design and Customization](#design-and-customization)
   - [Payments and Orders](#payments-and-orders)
   - [Mobile Version](#mobile-version)

5. [Costs and Versions](#costs-and-versions)
   - [Community Version](#community-version)
   - [Enterprise Version](#enterprise-version)
   - [Alternatives](#alternatives)

6. [Security and Backups](#security-and-backups)
   - [Data Protection](#data-protection)
   - [Backup System](#backup-system)
   - [Restore](#restore)

7. [Documentation and Support](#documentation-and-support)
   - [User Guides](#user-guides)
   - [Technical Support](#technical-support)
   - [Updates](#updates)

8. [Extensibility and Customization](#extensibility-and-customization)
   - [Module System](#module-system)
   - [Custom Configurations](#custom-configurations)
   - [Performance Tuning](#performance-tuning)

---

# Installation Guide

## Domain Configuration

1. Purchase a domain name (OVH, Gandi, Namecheap, Cloudflare, etc.)
2. DNS Setup:
   - Add an A record in your DNS zone
   - Target = your server's public IP
   - For dynamic IP: use DuckDNS or Cloudflare Tunnel

## Server Installation

1. Preparation:

   ```bash
   git clone https://github.com/XnsYT/odoo-server-installer.git
   cd odoo-server-installer
   chmod +x odoo-server-installer-en.sh
   sudo ./odoo-server-installer-en.sh
   ```

2. The script will automatically configure:
   - Nginx and SSL
   - Database
   - Security
   - Monitoring
   - Backups

## Advanced Options

The installer now supports additional options:

```bash
./odoo-server-installer-en.sh --help
```

Key new features:

- **Dry-run mode**: Simulate installation without changing your system
  ```bash
  sudo ./odoo-server-installer-en.sh --dry-run
  ```

- **Distribution detection**: Automatic adaptation to your Linux distribution
- **Cache system**: Skip already completed operations during re-runs
- **Parallel execution**: Speed up installation by running independent tasks in parallel
- **Enhanced validation**: Better domain, email, and service validation

---

## Initial Setup

1. Go to: https://your-domain
2. Create your database
3. Configure your company

---

# Access and Usage

## First Launch
- Database creation
- Company configuration
- Import initial data

## User Management
- Create user accounts
- Assign permissions
- Set up 2FA

## Initial Configuration
- Essential modules
- System settings
- Customization

---

# Monitoring and Supervision

## Dashboards
- Grafana: real-time metrics
- Netdata: system performance
- Prometheus: data collection

## Alert System
- Configurable notifications
- Alert thresholds
- Automated actions

## Log Management
- Centralized logs
- Real-time analysis
- History

---

# E-commerce and Website

## Design and Customization
- Professional themes
- Advanced customization
- Mobile adaptation

## Payments and Orders
- Secure payments
- Order management
- Stock tracking

## Mobile Version
- Native app
- PWA
- Optimized interface

---

# Costs and Versions

## Community Version (Free)
- Full features
- No limitations
- Community support

## Enterprise Version
- Additional features
- Official support
- Assisted migration

## Alternatives
- Community modules
- Third-party integrations
- Open source solutions

---

# Security and Backups

## Data Protection
- Encryption
- Access control
- Auditing

## Backup System
- Automated backups
- Integrity checks
- Configurable retention

## Restore
- Tested procedures
- Restore points
- Business continuity

---

# Documentation and Support

## User Guides
- Detailed procedures
- Use cases
- Best practices

## Technical Support
- Community forums
- Knowledge base
- Technical documentation

## Updates
- Security
- Features
- Compatibility

---

# Extensibility and Customization

## Module System
The installer now supports a modular approach:

- **External modules**: Extend functionality through external script modules
- **Custom modules**: Create your own modules for specialized deployments
- **Module examples**: Built-in examples to get started

```bash
# Location of modules
./modules/
```

## Custom Configurations

- **Dynamic tuning**: Automatic optimization based on available resources
- **Distribution-specific tweaks**: Optimal configurations for different Linux distributions
- **Virtualization detection**: Parameter adjustments for virtual environments

## Performance Tuning

- **Parallel processing**: Multi-threading support for faster installation
- **Caching system**: Skip already completed steps when re-running
- **Resource-based optimization**: PostgreSQL, Redis, and Nginx settings optimized for your hardware

---

Thank you for checking out **odoo-server-installer**! If you have questions, ideas, or want to contribute, feel free to open an issue or pull request. Your feedback is welcome and helps make this project better for everyone.

## Recent Updates

### Version 1.4.0
- Centralized configuration: All configuration variables are grouped at the top of the script, with support for .env overrides.
- Consistent naming: All functions and variables use snake_case for clarity and maintainability.
- Improved modularity: Functions are grouped by logical sections, and code duplication has been removed.
- Enhanced error handling and security: Stricter permissions, improved traps, and secret masking in all logs.
- Performance optimizations: More parallelism for package installation and system checks, batch operations for efficiency.
- Expanded validation: More robust input validation for domains, emails, and passwords.
- Advanced logging and monitoring: Log rotation, retention, color-coded output, and centralized log forwarding (ELK/Filebeat).
- User experience improvements: Progress indicators, clearer prompts, dry-run support, and auto-generated install summary.
- Cloud backup and monitoring: Native rclone multi-target backup, Uptime Kuma deployment, Slack/Telegram alert integration.
- Secrets management: HashiCorp Vault and Bitwarden CLI integration for secure secrets storage.
- Wildcard certificate automation: acme.sh integration for DNS-based wildcard SSL certificates.
- Modern reverse proxy: Traefik deployment option with auto-configuration.
- SSO and VPN: SSO assistant for Odoo/admin tools, WireGuard VPN deployment.
- Migration, HA, and security: Migration/cloning tools, HA support (Patroni/HAProxy), advanced security (CrowdSec, auditd, Falco).
- Automatic update and reporting: Scheduled updates and email reports.
- Self-update and dependency checks: Installer can update itself and check for outdated dependencies.
- Testing and quality: Unit tests for all critical functions, smoke tests after install, improved uninstall and rollback.

### Version 1.3.0
- partially Multi-language support for logs and user messages (11 languages: en, fr, es, ar, hi, zh, pt, ru, ja, de, id)
- Secure deletion/encryption of sensitive files (logs, summaries) after install
- Improved uninstall: interactive confirmation, --purge option, uninstall summary, and use of global variables for all paths
- Granular rollback actions for each critical step
- Binary presence checks and alternatives for systemctl, ufw, etc.
- Trap for cleanup on interruption (SIGINT, SIGTERM)
- More unit tests (backup/restore, permissions, etc.)
- Enhanced help output: language selection, new options, and usage examples

### Version 1.2.0
- Major security hardening: SELinux/AppArmor profiles, advanced firewall, audit logging, 2FA, and secrets management
- Disaster recovery: full backup/restore automation, integrity checks, and rollback system
- Advanced monitoring: Prometheus, Grafana, Loki, Netdata, Odoo Prometheus exporter, alerting, and log centralization
- Dynamic tuning: automatic resource-based optimization for PostgreSQL, Redis, Nginx, and Odoo
- Modular system: external module support, example modules, and easier customization
- Parallel execution: faster installation with multi-core support and improved cache system
- Cloud & container support: Docker/Compose, S3 backup, Cloudflare Tunnel, and DDNS automation
- Enhanced documentation: auto-generated server summary, disaster recovery guide, and improved inline help
- Improved validation: stricter domain/email checks, interactive and auto modes, and better error reporting
- New advanced options: encrypted backups, password rotation, staging environment, load balancing, CDN, and more

### Version 1.1.0
- Added modular architecture for better extensibility
- Implemented dry-run mode for testing without system changes
- Added support for Alpine Linux and improved compatibility with other distributions
- Enhanced validation and error handling
- Added caching system for idempotent operations
- Implemented parallel execution for faster installation
- Comprehensive preliminary checks before installation
- Dynamic resource allocation based on system capabilities
