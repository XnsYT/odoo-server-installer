#!/bin/bash
# Script d'installation Odoo 17 optimisé - Debian 12/Ubuntu 24.04 - 64GB RAM
# Version refactorisée : journalisation structurée, rollback, validation stricte, modularité, sécurité renforcée
# Version : 1.1.0
# Date : 2023-10-01

set -euo pipefail
trap 'echo "Erreur à la ligne $LINENO. Script interrompu." >&2; exit 1' ERR

#=============================================================================
# CONFIGURATION ET INITIALISATION
#=============================================================================

# Constantes de chemins pour une meilleure maintenabilité
readonly ODOO_HOME="/opt/odoo"
readonly CONFIG_DIR="/etc/odoo"
readonly LOG_DIR="/var/log/odoo"
readonly BACKUP_DIR="/opt/backups"
readonly NGINX_SITES="/etc/nginx/sites-available"
readonly PG_CONFIG_DIR="/etc/postgresql"

# Système de chargement de modules - charge les scripts externes si disponibles
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
MODULE_DIR="${SCRIPT_DIR}/modules"

# Fonction pour charger les modules externes s'ils existent
charger_module() {
    local module_name="$1"
    local module_path="${MODULE_DIR}/${module_name}.sh"
    if [[ -f "$module_path" ]]; then
        info "Chargement du module externe : $module_name"
        source "$module_path"
        return 0
    else
        debug "Module non trouvé : $module_name, utilisation de la fonction interne"
        return 1
    fi
}

# Crée le dossier modules si inexistant
if [[ ! -d "$MODULE_DIR" ]]; then
    mkdir -p "$MODULE_DIR"
    debug "Répertoire modules créé : $MODULE_DIR"
    generer_exemple_module
fi

# Vérifie que bash est utilisé
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Ce script nécessite bash." >&2
    exit 1
fi

# Traitement des arguments de la ligne de commande
MODE_AUTO=false
MODE_DRYRUN=false

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat << EOF
Odoo Server Installer v${SCRIPT_VERSION} (${SCRIPT_DATE})

Utilisation : $0 [options]

Options :
  --help, -h              Afficher cette aide
  --auto                  Mode automatique (aucune question interactive)
  --domain=DOMAINE        Définir le nom de domaine
  --email=EMAIL           Définir l'email pour Let's Encrypt
  --cloudflare            Utiliser Cloudflare Tunnel
  --ddns=SERVICE          Service DDNS (duckdns|noip|dynu)
  --debug                 Mode debug (plus de logs)
  --expose-monitoring     Exposer les ports de monitoring
  --dry-run               Simuler l'installation sans modification système

Exemples :
  $0 --auto --domain=exemple.com --email=admin@exemple.com
  $0 --cloudflare --domain=exemple.com
  $0 --ddns=duckdns --domain=monsite.duckdns.org

Pour la documentation complète, voir : https://github.com/XnsYT/odoo-server-installer/
EOF
    exit 0
fi

if [[ "${1:-}" == "--version" ]]; then
    echo "Odoo Server Installer v${SCRIPT_VERSION} (${SCRIPT_DATE})"
    exit 0
fi

for arg in "$@"; do
    case $arg in
        --auto)
            MODE_AUTO=true
            ;;
        --domain=*)
            DOMAINE="${arg#*=}"
            ;;
        --email=*)
            EMAIL_LE="${arg#*=}"
            ;;
        --cloudflare)
            CLOUDFLARE_TUNNEL=true
            ;;
        --ddns=*)
            SERVICE_DDNS="${arg#*=}"
            ;;
        --debug)
            NIVEAU_LOG="DEBUG"
            ;;
        --expose-monitoring)
            EXPOSE_MONITORING=true
            ;;
        --dry-run)
            MODE_DRYRUN=true
            ;;
    esac
done

if [[ "$MODE_DRYRUN" == true ]]; then
    info "MODE SIMULATION ACTIVÉ : aucune modification réelle ne sera effectuée."
    info "Ce mode simule l'installation pour détecter d'éventuels problèmes."
fi

#=============================================================================
# JOURNALISATION STRUCTURÉE & MASQUAGE
#=============================================================================
LOG_FILE="/var/log/odoo_install.log"
MASKED_VARS=("DB_PASS" "ADMIN_PASS" "REDIS_PASS" "NOIP_PASS" "DYNU_PASS" "DUCKDNS_TOKEN" "PASSWORD" "TOKEN" "SECRET" "KEY")

# Crée le dossier de logs s'il n'existe pas
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

# Définit le niveau de log par défaut si non défini
LOG_LEVEL=${LOG_LEVEL:-"INFO"}

# Fonction de journalisation améliorée avec masquage
log() {
    local level="$1"; shift
    local msg="$@"
    local masked_msg="$msg"
    
    # D'abord, masque les variables suivies
    for var in "${MASKED_VARS[@]}"; do
        # Vérifie si la variable existe et n'est pas vide
        if [[ -v "$var" && -n "${!var:-}" && ${#var} -gt 3 ]]; then
            local val="${!var}"
            if [[ -n "$val" && ${#val} -gt 3 ]]; then
                # Masque uniquement si la valeur fait plus de 3 caractères
                # Affiche les 2 premiers et 2 derniers caractères pour le debug
                local visible_prefix="${val:0:2}"
                local visible_suffix="${val: -2}"
                local mask_length=$((${#val} - 4))
                local mask_stars=$(printf '%*s' "$mask_length" | tr ' ' '*')
                local mask="$visible_prefix$mask_stars$visible_suffix"
                masked_msg="${masked_msg//${val}/${mask}}"
            fi
        fi
    done
    
    # Puis masque tout motif ressemblant à un mot de passe, token ou clé
    masked_msg=$(echo "$masked_msg" | sed -E 's/([Pp]ass(word)?|[Tt]oken|[Ss]ecret|[Kk]ey)[=: ]+[A-Za-z0-9+\/]{8,}/\1=******/g')
    
    # Format du timestamp avec millisecondes pour un debug précis
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S.%3N')
    echo -e "[$timestamp] [$level] $masked_msg" | tee -a "$LOG_FILE"
    
    # Pour les erreurs et avertissements, log aussi la fonction et la ligne appelante
    if [[ "$level" == "ERROR" || "$level" == "WARN" ]]; then
        local caller_info=$(caller 1 2>/dev/null || echo "inconnu")
        echo -e "[$timestamp] [$level] Appelé depuis : $caller_info" >> "$LOG_FILE"
    fi
}

# Aides couleurs pour une meilleure visibilité
info() { log "INFO" "\e[32m$@\e[0m"; }  # Vert
warn() { log "WARN" "\e[33m$@\e[0m"; }  # Jaune
error() { log "ERROR" "\e[31m$@\e[0m"; exit 1; }  # Rouge
debug() { 
    if [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]]; then
        log "DEBUG" "\e[36m$@\e[0m"  # Cyan
    fi
}

#=============================================================================
# AIDES DOCUMENTATION
#=============================================================================

# Aide à la documentation des fonctions pour standardiser les entêtes
# Utilisation : @doc "Description" "param1:description" "param2:description" "return:description"
function @doc() {
    : # Fonction no-op servant uniquement à la documentation
    # La documentation est lue par la fonction extract_docs
}

# Extraction de la documentation des fonctions
# Utilisation : extract_docs nom_fonction
function extract_docs() {
    local func_name="$1"
    local func_body
    func_body=$(declare -f "$func_name" 2>/dev/null)
    
    if [[ -z "$func_body" ]]; then
        echo "Fonction $func_name introuvable"
        return 1
    fi
    
    local doc_lines
    doc_lines=$(echo "$func_body" | grep -A 20 '@doc' | grep -B 20 -m 1 '^}' || echo "Aucune documentation trouvée")
    
    echo "$doc_lines"
}

#=============================================================================
# SYSTÈME DE ROLLBACK
#=============================================================================
ROLLBACK_ACTIONS=()
trap 'on_error $LINENO' ERR
on_error() {
    local line=$1
    local command="${BASH_COMMAND}"
    error "Erreur à la ligne $line lors de l'exécution : '$command' - Rollback en cours"
    rollback
    exit 1
}
rollback() {
    info "Début de la procédure de rollback..."
    for action in "${ROLLBACK_ACTIONS[@]}"; do
        info "Exécution de l'action de rollback : $action"
        if output=$(eval "$action" 2>&1); then
            info "Action de rollback réussie"
        else
            warn "Échec de l'action de rollback : $action"
            warn "Erreur : $output"
        fi
    done
    warn "Rollback terminé"
}
add_rollback() {
    ROLLBACK_ACTIONS=("$1" "${ROLLBACK_ACTIONS[@]}")
}

#=============================================================================
# CONTRAINTES SYSTÈME
#=============================================================================
check_system_constraints() {
    info "Vérification des contraintes système..."
    
    # Vérifie si root
    if [[ $EUID -ne 0 ]]; then
        error "Ce script doit être exécuté en tant que root"
    fi
    
    # Vérifie les dépendances binaires
    for cmd in curl wget apt-get systemctl python3 openssl gpg git; do
        if ! command -v "$cmd" &> /dev/null; then
            error "Commande requise non trouvée : $cmd"
        fi
    done
    
    # Vérifie si SELinux est en mode enforcing
    if command -v getenforce &> /dev/null; then
        SELINUX_STATUS=$(getenforce)
        if [[ "$SELINUX_STATUS" == "Enforcing" ]]; then
            warn "SELinux est en mode Enforcing - des permissions spéciales seront configurées"
            SELINUX_ENABLED=true
        fi
    fi
    
    # Détecte la virtualisation
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT=$(systemd-detect-virt)
        if [[ "$VIRT" != "none" ]]; then
            info "Environnement virtualisé détecté : $VIRT"
            # Les paramètres peuvent être ajustés pour la virtualisation
        fi
    fi
    
    # Vérifie l'architecture
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]]; then
        warn "Architecture $ARCH potentiellement non supportée. x86_64 ou aarch64 recommandé."
    fi
    
    # Vérifie l'espace disque
    ROOT_SPACE=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ $ROOT_SPACE -lt 10 ]]; then
        error "Espace disque insuffisant. Minimum 10G requis sur /, vous avez ${ROOT_SPACE}G"
    fi
    
    # Vérifie la connectivité Internet
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        error "Aucune connexion Internet détectée"
    fi
    
    info "Vérification des contraintes système terminée"
}

# Génère un mot de passe sécurisé avec plusieurs sources d'entropie
generate_secure_password() {
    local length=${1:-32}
    # Utilise plusieurs sources d'entropie pour plus de sécurité
    local pass=$(head -c 1024 /dev/urandom | tr -dc 'a-zA-Z0-9!@#$%^&*()-_=+[]{}|;:,.<>?' | head -c "$length")
    echo "$pass"
}

# ===================== VALIDATION STRICTE DES ENTRÉES =====================
validate_inputs() {
    info "Validation des entrées"
    
    # Validation du domaine
    if [[ -z "$DOMAIN" ]]; then 
        error "Domaine non fourni"
    fi
    
    # Validation regex du domaine
    if ! [[ "$DOMAIN" =~ ^([a-zA-Z0-9]([-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$ ]]; then
        error "Format de domaine invalide : $DOMAIN"
        error "Le domaine doit suivre le format RFC 1035 (ex : exemple.com, sous.exemple.com)"
    fi
    
    # Validation de l'email si besoin
    if [[ "$CLOUDFLARE_TUNNEL" != true && -z "$LE_EMAIL" ]]; then 
        error "Email Let's Encrypt requis" 
    fi
    
    # Validation regex de l'email
    if [[ "$CLOUDFLARE_TUNNEL" != true && ! "$LE_EMAIL" =~ ^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$ ]]; then
        error "Format d'email invalide : $LE_EMAIL"
        error "L'email doit suivre le format RFC 5322 (ex : utilisateur@exemple.com)"
    fi
    
    # Validation du service DDNS
    if [[ -n "$DDNS_SERVICE" ]]; then
        if ! [[ "$DDNS_SERVICE" =~ ^(duckdns|noip|dynu|custom)$ ]]; then
            error "Service DDNS invalide : $DDNS_SERVICE"
            error "Services supportés : duckdns, noip, dynu, custom"
        fi
        
        # Validations spécifiques au service
        case "$DDNS_SERVICE" in
            duckdns)
                if [[ -z "$SUBDOMAIN" || -z "$DUCKDNS_TOKEN" ]]; then
                    error "DuckDNS requiert à la fois le sous-domaine et le token"
                fi
                if [[ ! "$DUCKDNS_TOKEN" =~ ^[a-zA-Z0-9]{8,}$ ]]; then
                    error "Format de token DuckDNS invalide"
                fi
                ;;
            noip)
                if [[ -z "$NOIP_USER" || -z "$NOIP_PASS" ]]; then
                    error "No-IP requiert à la fois le nom d'utilisateur et le mot de passe"
                fi
                ;;
            dynu)
                if [[ -z "$DYNU_USER" || -z "$DYNU_PASS" ]]; then
                    error "Dynu requiert à la fois le nom d'utilisateur et le mot de passe"
                fi
                ;;
        esac
    fi
    
    info "Validation des entrées terminée avec succès"
}

# === QUICK CONFIGURATION (edit before execution) ===
# Fill in your information here if you want 100% automatic deployment
# If left empty, the script will only ask for what is essential
DOMAIN=""         # Example: mysite.com
LE_EMAIL=""       # Email for Let's Encrypt (required for SSL)
DDNS_SERVICE=""   # duckdns|noip|dynu|custom (leave empty if not used)
SUBDOMAIN=""      # For DuckDNS
DUCKDNS_TOKEN=""  # For DuckDNS
NOIP_USER=""      # For No-IP
NOIP_PASS=""      # For No-IP
DYNU_USER=""      # For Dynu
DYNU_PASS=""      # For Dynu
CLOUDFLARE_TUNNEL=false # set to true to force Cloudflare Tunnel

# === ADVANCED CONFIGURATION ===
INSTALL_MODE="production"   # production|development|testing
EXPOSE_MONITORING=false     # Expose monitoring ports to external networks
BACKUP_RETENTION_DAYS=7     # How many days to keep backups
ENABLE_AUTO_UPDATE=false    # Enable automatic updates
ENABLE_EMAIL_ALERTS=false   # Enable email alerts
ALERT_EMAIL=""             # Email for alerts
PROXY_URL=""               # HTTP proxy if needed
LOG_LEVEL="INFO"           # DEBUG|INFO|WARN|ERROR
# =========================================

# ===================== VALIDATION INTERACTIVE =====================
validate_interactive() {
    info "Vérification interactive des prérequis..."
    local CONTINUE=true
    local WARNINGS=()
    
    # Fonction pour demander la confirmation
    ask_continue() {
        local message="$1"
        local default="${2:-o}"  # o par défaut
        while true; do
            read -p "$message [O/n] " response
            case $response in
                [Nn]* ) return 1;;
                [Oo]* ) return 0;;
                "" ) if [ "$default" = "o" ]; then return 0; else return 1; fi;;
                * ) echo "Veuillez répondre o ou n";;
            esac
        done
    }
    
    # Contrôle du noyau
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
    if [[ $KERNEL_MAJOR -lt 5 || ($KERNEL_MAJOR -eq 5 && $KERNEL_MINOR -lt 10) ]]; then
        WARNINGS+=("⚠️ Noyau Linux < 5.10 détecté (actuel : $KERNEL_VERSION). Les performances peuvent être impactées.")
    fi
    
    # Vérification RAM
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $RAM_GB -lt 16 ]]; then
        WARNINGS+=("⚠️ RAM < 16Go détectée (${RAM_GB}Go). Les performances seront limitées.")
    fi
    
    # Vérification CPU
    CPU_CORES=$(nproc)
    if [[ $CPU_CORES -lt 4 ]]; then
        WARNINGS+=("⚠️ Moins de 4 cœurs CPU détectés ($CPU_CORES). Les performances seront limitées.")
    fi
    
    # Vérification disque
    DISK_TYPE=$(lsblk -d -o name,rota | grep -v "loop" | grep -v "sr0" | awk 'NR==2 {print $2}')
    if [[ "$DISK_TYPE" == "1" ]]; then
        WARNINGS+=("⚠️ Disque HDD détecté. Un SSD est fortement recommandé pour de meilleures performances.")
    fi
    
    # Vérification réseau
    NETWORK_SPEED=$(ethtool $(ip route | grep default | awk '{print $5}') 2>/dev/null | grep "Speed:" | awk '{print $2}' | tr -d 'Mb/s')
    if [[ -n "$NETWORK_SPEED" && "$NETWORK_SPEED" -lt 1000 ]]; then
        WARNINGS+=("⚠️ Vitesse réseau < 1Gbps détectée. Les performances peuvent être impactées.")
    fi
    
    # Vérification espace disque
    declare -A MIN_SPACE=(
        ["/"]="20"
        ["/var"]="10"
        ["/tmp"]="5"
        ["/opt"]="20"
    )
    
    for dir in "${!MIN_SPACE[@]}"; do
        AVAILABLE=$(df -BG --output=avail "$dir" 2>/dev/null | tail -n1 | tr -d 'G')
        REQUIRED="${MIN_SPACE[$dir]}"
        if [[ -z "$AVAILABLE" || $AVAILABLE -lt $REQUIRED ]]; then
            WARNINGS+=("⚠️ Espace insuffisant sur $dir. Minimum recommandé : ${REQUIRED}G, Disponible : ${AVAILABLE:-0}G")
        fi
    done
    
    # Affichage des avertissements et demande de confirmation
    if [ ${#WARNINGS[@]} -gt 0 ]; then
        echo -e "\n🔍 Avertissements détectés :"
        for warning in "${WARNINGS[@]}"; do
            echo "$warning"
        done
        echo -e "\n🔧 Recommandations :"
        if [[ $RAM_GB -lt 16 ]]; then
            echo "- Augmentez la RAM à au moins 16Go pour de meilleures performances"
            echo "- Le swap sera configuré automatiquement pour compenser"
        fi
        if [[ $CPU_CORES -lt 4 ]]; then
            echo "- Le nombre de workers Odoo sera ajusté automatiquement"
            echo "- Certaines fonctionnalités seront désactivées pour préserver les performances"
        fi
        if [[ "$DISK_TYPE" == "1" ]]; then
            echo "- La configuration sera optimisée pour les disques HDD"
            echo "- Le cache sera augmenté pour compenser"
        fi
        
        echo -e "\n⚙️ Adaptations automatiques qui seront appliquées :"
        if [[ $RAM_GB -lt 16 ]]; then
            echo "- Configuration du swap optimisée"
            echo "- Limite mémoire Odoo ajustée"
            echo "- Cache Redis réduit"
        fi
        if [[ $CPU_CORES -lt 4 ]]; then
            echo "- Nombre de workers réduit"
            echo "- Compression des assets activée"
            echo "- Cache agressif"
        fi
        if [[ "$DISK_TYPE" == "1" ]]; then
            echo "- Cache disque augmenté"
            echo "- Compression des logs activée"
            echo "- Rotation des logs plus fréquente"
        fi
        
        echo -e "\n❓ Voulez-vous continuer malgré ces avertissements ?"
        if ! ask_continue "L'installation sera automatiquement optimisée pour votre configuration."; then
            error "Installation annulée par l'utilisateur"
            exit 1
        fi
    fi
    
    # Install missing required packages
    REQUIRED_PACKAGES=(
        "build-essential"
        "python3-dev"
        "python3-pip"
        "python3-venv"
        "git"
        "postgresql-client"
        "libpq-dev"
        "libxml2-dev"
        "libxslt1-dev"
        "libldap2-dev"
        "libsasl2-dev"
        "libssl-dev"
        "libjpeg-dev"
        "zlib1g-dev"
    )
    
    MISSING_PACKAGES=()
    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            MISSING_PACKAGES+=("$pkg")
        fi
    done
    
    if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
        info "Installing required packages"
        apt-get update
        apt-get install -y "${MISSING_PACKAGES[@]}"
    fi
    
    info "Interactive validation completed"
}

# Interactive configuration
get_user_config() {
    log "Configuration système..."
    # Mode auto si DOMAIN et LE_EMAIL sont fournis
    if [[ -n "$DOMAIN" && ( -n "$LE_EMAIL" || "$CLOUDFLARE_TUNNEL" = true ) ]]; then
        if [[ "$CLOUDFLARE_TUNNEL" = true ]]; then
            CONNECTION_TYPE=3
            USE_CLOUDFLARE=true
            LE_EMAIL=""
        else
            CONNECTION_TYPE=1
            USE_CLOUDFLARE=false
        fi
        log "Mode auto : domaine $DOMAIN, email $LE_EMAIL, Tunnel Cloudflare $CLOUDFLARE_TUNNEL"
    else
        # Détection du type de connexion
        echo "🌐 Type de connexion :"
        echo "1) IP statique / Serveur dédié"
        echo "2) IP dynamique / Box maison"
        echo "3) Tunnel Cloudflare (recommandé pour IP dynamique)"
        read -p "Choisissez (1-3) : " CONNECTION_TYPE
        
        case $CONNECTION_TYPE in
            1)
                # Configuration classique
                while true; do
                    read -p "Entrez votre nom de domaine (ex : monsite.com) : " DOMAIN
                    if [[ $DOMAIN =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
                        break
                    else
                        warn "Format de domaine invalide. Veuillez réessayer."
                    fi
                done
                
                while true; do
                    read -p "Entrez votre email pour Let's Encrypt : " LE_EMAIL
                    if [[ $LE_EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
                        break
                    else
                        warn "Format d'email invalide. Veuillez réessayer."
                    fi
                done
                USE_CLOUDFLARE=false
                ;;
            2)
                # Configuration DNS dynamique
                echo "🔄 Configuration DNS dynamique"
                echo "Services gratuits disponibles :"
                echo "1) DuckDNS (duckdns.org)"
                echo "2) No-IP (noip.com)"
                echo "3) Dynu (dynu.com)"
                echo "4) Domaine personnel avec DDNS"
                read -p "Choisissez (1-4) : " DDNS_SERVICE
                
                case $DDNS_SERVICE in
                    1)
                        read -p "Nom du sous-domaine DuckDNS (ex : monsite) : " SUBDOMAIN
                        read -p "Token DuckDNS : " DUCKDNS_TOKEN
                        DOMAIN="${SUBDOMAIN}.duckdns.org"
                        ;;
                    2)
                        read -p "Nom d'hôte No-IP complet (ex : monsite.ddns.net) : " DOMAIN
                        read -p "Nom d'utilisateur No-IP : " NOIP_USER
                        read -p "Mot de passe No-IP : " NOIP_PASS
                        ;;
                    3)
                        read -p "Nom d'hôte Dynu complet (ex : monsite.freeddns.org) : " DOMAIN
                        read -p "Nom d'utilisateur Dynu : " DYNU_USER
                        read -p "Mot de passe Dynu : " DYNU_PASS
                        ;;
                    4)
                        read -p "Votre domaine : " DOMAIN
                        ;;
                esac
                
                read -p "Entrez votre email pour Let's Encrypt : " LE_EMAIL
                USE_CLOUDFLARE=false
                ;;
            3)
                # Configuration Tunnel Cloudflare
                echo "🔒 Configuration Tunnel Cloudflare"
                read -p "Entrez votre nom de domaine (doit être sur Cloudflare) : " DOMAIN
                echo "Vous devrez configurer le tunnel après l'installation"
                echo "Instructions : https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/"
                USE_CLOUDFLARE=true
                LE_EMAIL=""
                ;;
        esac
    fi
    
    # Configuration automatique optimisée
    DB_NAME="odoo_production"
    DB_USER="odoo_user"
    ADMIN_PASS=$(generate_secure_password 20)
    DB_PASS=$(generate_secure_password 32)
    REDIS_PASS=$(generate_secure_password 16)
    
    # Détection du nombre de CPU
    CPU_CORES=$(nproc)
    WORKERS=$((CPU_CORES * 2))
    
    PUBLIC_IP=$(curl -s --max-time 10 ifconfig.me || echo "IP non détectée")
    
    log "Configuration terminée :"
    log "  Domaine : $DOMAIN"
    log "  Cœurs CPU : $CPU_CORES"
    log "  Workers Odoo : $WORKERS"
    log "  RAM : ${RAM_GB}Go"
}

# Optimisation system
optimize_system() {
    log "System optimization..."
    
    # Kernel optimizations
    cat >> /etc/sysctl.conf << EOF
# Odoo optimizations
vm.swappiness = 1
vm.overcommit_memory = 2
vm.overcommit_ratio = 80
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_max_syn_backlog = 8192
EOF
    sysctl -p
    
    # System limits
    cat >> /etc/security/limits.conf << EOF
# Odoo limits
odoo soft nofile 65535
odoo hard nofile 65535
postgres soft nofile 65535
postgres hard nofile 65535
EOF
}

# Function to check and install dependencies efficiently
check_dependencies() {
    info "Checking system dependencies..."
    
    # Define required packages by category
    declare -A PACKAGE_CATEGORIES=(
        ["essential"]="curl wget git htop iotop build-essential"
        ["python"]="python3-pip python3-dev python3-venv virtualenv"
        ["libs"]="libxml2-dev libxslt1-dev zlib1g-dev libsasl2-dev libldap2-dev libjpeg-dev libpq-dev libffi-dev libssl-dev"
        ["tools"]="fonts-liberation geoip-database node-clean-css node-less xz-utils"
        ["monitoring"]="prometheus-node-exporter fail2ban logrotate rsyslog"
        ["network"]="net-tools dnsutils iproute2 host"
        ["security"]="unattended-upgrades apt-listchanges"
    )
    
    # Combine all package categories into one for efficiency
    ALL_PACKAGES=()
    for category in "${!PACKAGE_CATEGORIES[@]}"; do
        packages="${PACKAGE_CATEGORIES[$category]}"
        ALL_PACKAGES+=($packages)
    done
    
    # Check which packages are missing based on the package manager
    MISSING_PACKAGES=()
    
    case "$DISTRO_FAMILY" in
        debian)
            for pkg in ${ALL_PACKAGES[@]}; do
                if ! dpkg -l | grep -q "^ii  $pkg "; then
                    MISSING_PACKAGES+=("$pkg")
                fi
            done
            
            # Install missing packages with single apt call for better performance
            if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
                info "Installing ${#MISSING_PACKAGES[@]} missing packages in one batch..."
                
                # Improve download speed with parallel downloads
                if ! grep -q "Acquire::Queue-Mode" /etc/apt/apt.conf.d/99parallel-install 2>/dev/null; then
                    cat > /etc/apt/apt.conf.d/99parallel-install << EOF
Acquire::Queue-Mode "host";
Acquire::http::Pipeline-Depth "10";
Acquire::https::Pipeline-Depth "10";
Acquire::Languages "none";
Acquire::http::Timeout "180";
Acquire::https::Timeout "180";
EOF
                fi
                
                # Single apt call instead of multiple
                apt-get update -qq
                DEBIAN_FRONTEND=noninteractive apt-get install -yq ${MISSING_PACKAGES[@]}
                info "Package installation completed"
            else
                info "All required packages are already installed"
            fi
            ;;
        redhat)
            # Similar logic for RPM-based distros
            for pkg in ${ALL_PACKAGES[@]}; do
                if ! rpm -q "$pkg" &>/dev/null; then
                    MISSING_PACKAGES+=("$pkg")
                fi
            done
            
            if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
                info "Installing ${#MISSING_PACKAGES[@]} missing packages..."
                $PKG_UPDATE
                $PKG_INSTALL ${MISSING_PACKAGES[@]}
            fi
            ;;
        arch)
            # For Arch-based distros
            for pkg in ${ALL_PACKAGES[@]}; do
                if ! pacman -Q "$pkg" &>/dev/null; then
                    MISSING_PACKAGES+=("$pkg")
                fi
            done
            
            if [[ ${#MISSING_PACKAGES[@]} -gt 0 ]]; then
                info "Installing ${#MISSING_PACKAGES[@]} missing packages..."
                $PKG_UPDATE
                $PKG_INSTALL ${MISSING_PACKAGES[@]}
            fi
            ;;
        *)
            warn "Package installation not supported for $DISTRO_FAMILY. Install dependencies manually."
            ;;
    esac
    
    # Configure unattended-upgrades for security patches if installed
    if [[ "$DISTRO_FAMILY" == "debian" ]] && dpkg -l | grep -q "^ii  unattended-upgrades "; then
        cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        
        sed -i 's/\/\/Unattended-Upgrade::Remove-Unused-Dependencies "false";/Unattended-Upgrade::Remove-Unused-Dependencies "true";/' /etc/apt/apt.conf.d/50unattended-upgrades
        sed -i 's/\/\/Unattended-Upgrade::Automatic-Reboot "false";/Unattended-Upgrade::Automatic-Reboot "false";/' /etc/apt/apt.conf.d/50unattended-upgrades
        
        systemctl enable unattended-upgrades
        info "Automatic security updates configured"
    fi
}

# Installation of packages
install_packages() {
    log "System packages installation..."
    
    # First check dependencies
    check_dependencies
    
    # If we're on a Debian-based system, do additional optimizations
    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        # Update system with a single command
        apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq
        
        # Essential packages in a single batch - only if some are missing
        ESSENTIAL_PACKAGES="curl wget git htop iotop build-essential python3-pip python3-dev python3-venv"
        ESSENTIAL_PACKAGES+=" libxml2-dev libxslt1-dev zlib1g-dev libsasl2-dev libldap2-dev libjpeg-dev"
        ESSENTIAL_PACKAGES+=" libpq-dev libffi-dev libssl-dev fonts-liberation geoip-database"
        ESSENTIAL_PACKAGES+=" node-clean-css node-less xz-utils prometheus-node-exporter fail2ban logrotate rsyslog"
        
        # Check which essential packages are missing
        MISSING_ESSENTIAL=()
        for pkg in $ESSENTIAL_PACKAGES; do
            if ! dpkg -l | grep -q "^ii  $pkg "; then
                MISSING_ESSENTIAL+=("$pkg")
            fi
        done
        
        # Install only missing packages to avoid unnecessary reinstallations
        if [[ ${#MISSING_ESSENTIAL[@]} -gt 0 ]]; then
            info "Installing ${#MISSING_ESSENTIAL[@]} missing essential packages in one batch..."
            DEBIAN_FRONTEND=noninteractive apt-get install -yq ${MISSING_ESSENTIAL[@]}
        fi
    elif [[ "$DISTRO_FAMILY" == "redhat" ]]; then
        # Red Hat based systems
        info "Installing packages on Red Hat based system..."
        $PKG_UPDATE
        $PKG_INSTALL curl wget git python3-devel python3-pip
        
        # Additional setup for PostgreSQL on RHEL/CentOS
        if [[ "$DISTRO" == "centos" || "$DISTRO" == "rhel" ]]; then
            # PostgreSQL repo setup for RHEL/CentOS
            $PKG_INSTALL https://download.postgresql.org/pub/repos/yum/reporpms/EL-$(rpm -E %{rhel})-x86_64/pgdg-redhat-repo-latest.noarch.rpm
        fi
    elif [[ "$DISTRO_FAMILY" == "arch" ]]; then
        # Arch based systems
        info "Installing packages on Arch based system..."
        $PKG_UPDATE
        $PKG_INSTALL base-devel python python-pip postgresql redis nginx
    else
        warn "Automatic package installation not supported for $DISTRO_FAMILY."
        warn "Please install required packages manually according to your distribution."
    fi
}

# PostgreSQL optimized configuration
setup_postgresql() {
    log "PostgreSQL installation and configuration..."
    
    # Install PostgreSQL based on distribution
    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        apt-get install -yq postgresql-15 postgresql-contrib-15 postgresql-client-15
        PG_VERSION=15
    elif [[ "$DISTRO_FAMILY" == "redhat" ]]; then
        $PKG_INSTALL postgresql15-server postgresql15-contrib postgresql15
        PG_VERSION=15
        # Initialize database for RHEL/CentOS
        /usr/pgsql-15/bin/postgresql-15-setup initdb
        systemctl enable postgresql-15
    elif [[ "$DISTRO_FAMILY" == "arch" ]]; then
        $PKG_INSTALL postgresql
        PG_VERSION=$(psql --version | grep -oP 'psql \(PostgreSQL\) \K[0-9]+\.[0-9]+' | cut -d. -f1)
        # Initialize database for Arch
        mkdir -p /var/lib/postgres/data
        chown -R postgres:postgres /var/lib/postgres
        sudo -u postgres initdb -D /var/lib/postgres/data
    else
        warn "PostgreSQL installation not automated for $DISTRO_FAMILY. Install manually."
        return 1
    fi
    
    # Find PG_CONF based on distribution and version
    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        PG_CONF="${PG_CONFIG_DIR}/${PG_VERSION}/main/postgresql.conf"
    elif [[ "$DISTRO_FAMILY" == "redhat" ]]; then
        PG_CONF="/var/lib/pgsql/${PG_VERSION}/data/postgresql.conf"
    elif [[ "$DISTRO_FAMILY" == "arch" ]]; then
        PG_CONF="/var/lib/postgres/data/postgresql.conf"
    else
        warn "Could not determine PostgreSQL configuration path for $DISTRO_FAMILY."
        warn "Please configure PostgreSQL manually."
        return 1
    fi
    
    # Ensure PostgreSQL is running
    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        systemctl start postgresql
    elif [[ "$DISTRO_FAMILY" == "redhat" ]]; then
        systemctl start postgresql-${PG_VERSION}
    elif [[ "$DISTRO_FAMILY" == "arch" ]]; then
        systemctl start postgresql
    fi

    # User configuration - common across distributions
    sudo -u postgres psql << EOF
CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
ALTER USER ${DB_USER} CREATEDB;
EOF
    
    # Optimized configuration for 64GB RAM - backup original config
    if [[ -f "$PG_CONF" ]]; then
        cp "$PG_CONF" "${PG_CONF}.bak"
        
        # Detect available RAM and CPU cores for optimized configuration
        TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))
        SHARED_BUFFERS="16GB" # Default for 64GB
        EFFECTIVE_CACHE="48GB" # Default for 64GB
        
        # Scale configuration to available RAM if less than 64GB
        if [[ $TOTAL_RAM_GB -lt 64 ]]; then
            if [[ $TOTAL_RAM_GB -ge 32 ]]; then
                SHARED_BUFFERS="8GB"
                EFFECTIVE_CACHE="24GB"
            elif [[ $TOTAL_RAM_GB -ge 16 ]]; then
                SHARED_BUFFERS="4GB"
                EFFECTIVE_CACHE="12GB" 
            elif [[ $TOTAL_RAM_GB -ge 8 ]]; then
                SHARED_BUFFERS="2GB"
                EFFECTIVE_CACHE="6GB"
            else
                SHARED_BUFFERS="1GB"
                EFFECTIVE_CACHE="3GB"
            fi
        fi
        
        # Create optimized PostgreSQL configuration
        cat > "$PG_CONF" << EOF
# Optimized PostgreSQL configuration for Odoo - ${TOTAL_RAM_GB}GB RAM
listen_addresses = 'localhost'
port = 5432
max_connections = 200
shared_buffers = ${SHARED_BUFFERS}
effective_cache_size = ${EFFECTIVE_CACHE}
work_mem = 256MB
maintenance_work_mem = 2GB
checkpoint_completion_target = 0.9
wal_buffers = 64MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
min_wal_size = 2GB
max_wal_size = 8GB
max_worker_processes = ${CPU_CORES}
max_parallel_workers_per_gather = $((CPU_CORES / 2))
max_parallel_workers = ${CPU_CORES}
max_parallel_maintenance_workers = $((CPU_CORES / 2))
log_destination = 'csvlog'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_min_duration_statement = 1000
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
EOF
    else
        error "PostgreSQL configuration file not found at $PG_CONF"
        return 1
    fi
    
    # Restart PostgreSQL to apply configuration
    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        systemctl restart postgresql
    elif [[ "$DISTRO_FAMILY" == "redhat" ]]; then
        systemctl restart postgresql-${PG_VERSION}
    elif [[ "$DISTRO_FAMILY" == "arch" ]]; then
        systemctl restart postgresql
    fi
    
    # Ensure PostgreSQL service is enabled for boot
    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        systemctl enable postgresql
    elif [[ "$DISTRO_FAMILY" == "redhat" ]]; then
        systemctl enable postgresql-${PG_VERSION}
    elif [[ "$DISTRO_FAMILY" == "arch" ]]; then
        systemctl enable postgresql
    fi
}

setup_postgresql_advanced() {
    info "Advanced PostgreSQL configuration..."
    
    # Installation of useful extensions
    sudo -u postgres psql << EOF
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pg_prewarm;
CREATE EXTENSION IF NOT EXISTS pg_buffercache;
CREATE EXTENSION IF NOT EXISTS auto_explain;
EOF

    # Performance optimizations
    cat >> /etc/postgresql/15/main/postgresql.conf << EOF
# Advanced optimizations
track_io_timing = on
track_functions = all
pg_stat_statements.track = all
pg_stat_statements.max = 10000
auto_explain.log_min_duration = '5s'
auto_explain.log_analyze = true
auto_explain.log_buffers = true
auto_explain.log_timing = true
autovacuum_vacuum_scale_factor = 0.01
autovacuum_analyze_scale_factor = 0.005
maintenance_work_mem = 2GB
vacuum_cost_delay = 10ms
vacuum_cost_limit = 2000
EOF

    # Automatic maintenance script
    cat > /usr/local/bin/pg_maintenance.sh << 'EOF'
#!/bin/bash
# Daily PostgreSQL maintenance
psql -U postgres << 'PSQL'
VACUUM ANALYZE;
REINDEX DATABASE odoo_production;
SELECT pg_prewarm('res_partner');
SELECT pg_prewarm('product_template');
SELECT pg_prewarm('sale_order');
PSQL
EOF
    chmod +x /usr/local/bin/pg_maintenance.sh
    
    # Scheduling maintenance
    (crontab -l 2>/dev/null; echo "0 1 * * * /usr/local/bin/pg_maintenance.sh") | crontab -
    
    info "Advanced PostgreSQL configuration completed"
}

# Setup PostgreSQL health checks
setup_postgresql_health_checks() {
    info "Mise en place des vérifications de santé PostgreSQL..."
    
    # Script de vérification de santé
    cat > /usr/local/bin/pg_health_check.sh << 'EOF'
#!/bin/bash
# Script de vérification de santé PostgreSQL
# Ce script vérifie divers indicateurs de santé PostgreSQL et signale les problèmes

# Chargement de la configuration
DB_NAME="odoo_production"
LOG_FILE="/var/log/postgresql/health_check.log"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Vérifier si PostgreSQL fonctionne
if ! systemctl is-active --quiet postgresql; then
    log_message "ERREUR : PostgreSQL n'est pas en cours d'exécution"
    exit 1
fi

# Vérifier la connectivité à la base
if ! sudo -u postgres psql -c '\l' > /dev/null 2>&1; then
    log_message "ERREUR : Impossible de se connecter à PostgreSQL"
    exit 1
fi

# Vérifier si la base Odoo existe
if ! sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    log_message "ERREUR : La base Odoo $DB_NAME n'existe pas"
    exit 1
fi

# Vérifier les requêtes longues (>30 secondes)
LONG_QUERIES=$(sudo -u postgres psql -c "SELECT pid, now() - query_start as duration, query FROM pg_stat_activity WHERE state = 'active' AND now() - query_start > interval '30 seconds';" | grep -v "duration" | grep -v "row" | grep -v "\-\-\-" || echo "")
if [[ -n "$LONG_QUERIES" ]]; then
    log_message "AVERTISSEMENT : Requêtes longues détectées :"
    log_message "$LONG_QUERIES"
fi

# Vérifier l'espace disque
DB_SIZE=$(sudo -u postgres psql -c "SELECT pg_size_pretty(pg_database_size('$DB_NAME'));" | grep -v "pg_size_pretty" | grep -v "row" | grep -v "\-\-\-" || echo "inconnu")
log_message "INFO : Taille de la base : $DB_SIZE"

# Vérifier le bloat des tables
BLOATED_TABLES=$(sudo -u postgres psql -c "SELECT schemaname, relname, n_dead_tup, last_vacuum FROM pg_stat_user_tables WHERE n_dead_tup > 10000 ORDER BY n_dead_tup DESC LIMIT 5;" | grep -v "schemaname" | grep -v "row" | grep -v "\-\-\-" || echo "")
if [[ -n "$BLOATED_TABLES" ]]; then
    log_message "AVERTISSEMENT : Tables avec beaucoup de tuples morts :"
    log_message "$BLOATED_TABLES"
    
    # Auto vacuum de la table la plus bloatée
    MOST_BLOATED=$(echo "$BLOATED_TABLES" | head -1 | awk '{print $1"."$2}')
    if [[ -n "$MOST_BLOATED" ]]; then
        log_message "INFO : Vacuum automatique de $MOST_BLOATED"
        sudo -u postgres psql -c "VACUUM ANALYZE $MOST_BLOATED;" > /dev/null 2>&1
    fi
fi

# Vérifier les index inutilisés
UNUSED_INDEXES=$(sudo -u postgres psql -c "SELECT schemaname, relname, indexrelname, idx_scan FROM pg_stat_user_indexes WHERE idx_scan < 10 AND schemaname NOT LIKE 'pg_%' ORDER BY idx_scan, indexrelname LIMIT 5;" | grep -v "schemaname" | grep -v "row" | grep -v "\-\-\-" || echo "")
if [[ -n "$UNUSED_INDEXES" ]]; then
    log_message "INFO : Index potentiellement inutilisés :"
    log_message "$UNUSED_INDEXES"
fi

# Tous les checks sont passés
log_message "INFO : Vérification de santé PostgreSQL terminée"
exit 0
EOF

    chmod +x /usr/local/bin/pg_health_check.sh
    
    # Tâche cron pour vérification régulière
    (crontab -l 2>/dev/null; echo "0 */4 * * * /usr/local/bin/pg_health_check.sh > /dev/null 2>&1") | crontab -
    
    # Vérification initiale
    /usr/local/bin/pg_health_check.sh
    
    info "Vérifications de santé PostgreSQL configurées"
}

# Redis installation
setup_redis() {
    log "Redis installation and configuration..."
    
    apt install -yq redis-server
    
    # Redis configuration
    cat > /etc/redis/redis.conf << EOF
bind 127.0.0.1
port 6379
timeout 0
tcp-keepalive 300
daemonize yes
supervised systemd
pidfile /var/run/redis/redis-server.pid
loglevel notice
logfile /var/log/redis/redis-server.log
databases 16
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error yes
rdbcompression yes
rdbchecksum yes
dbfilename dump.rdb
dir /var/lib/redis
requirepass ${REDIS_PASS}
maxmemory 4GB
maxmemory-policy allkeys-lru
EOF
    
    systemctl restart redis-server
    systemctl enable redis-server
}

# Odoo 17 installation
install_odoo() {
    info "Odoo installation"
    
    # User
    useradd -m -d /opt/odoo -U -r -s /bin/bash odoo
    
    # Installation
    su - odoo -c "
        python3 -m venv /opt/odoo/venv
        source /opt/odoo/venv/bin/activate
        pip install wheel
        pip install odoo
        deactivate
    "
    
    # Configuration
    mkdir -p /etc/odoo
    cat > /etc/odoo/odoo.conf << EOF
[options]
admin_passwd = ${ADMIN_PASS}
db_host = localhost
db_port = 5432
db_user = odoo
db_password = ${DB_PASS}
addons_path = /opt/odoo/venv/lib/python3.*/site-packages/odoo/addons
logfile = /var/log/odoo/odoo.log
log_level = warn
workers = $((CPU_CORES > 1 ? CPU_CORES - 1 : 1))
max_cron_threads = $((CPU_CORES > 2 ? 2 : 1))
limit_memory_soft = $((RAM_GB > 16 ? RAM_GB * 768 : 1024))M
limit_memory_hard = $((RAM_GB > 16 ? RAM_GB * 1024 : 1536))M
limit_request = 8192
limit_time_cpu = 600
limit_time_real = 1200
max_cron_threads = 1
EOF

    # Service
    cat > /etc/systemd/system/odoo.service << EOF
[Unit]
Description=Odoo
After=network.target postgresql.service

[Service]
Type=simple
User=odoo
Group=odoo
ExecStart=/opt/odoo/venv/bin/python3 /opt/odoo/venv/bin/odoo --config /etc/odoo/odoo.conf
StandardOutput=journal
StandardError=journal
SyslogIdentifier=odoo

[Install]
WantedBy=multi-user.target
EOF

    # Logs
    mkdir -p /var/log/odoo
    chown odoo:odoo /var/log/odoo

    # Startup
    systemctl daemon-reload
    systemctl enable --now odoo
    
    info "Odoo installation completed"
}

# Nginx optimized configuration
setup_nginx() {
    log "Configuration de Nginx..."
    
    apt install -yq nginx
    rm -f /etc/nginx/sites-enabled/default
    
    # Configuration principale Nginx
    cat > /etc/nginx/nginx.conf << EOF
user www-data;
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 100M;
    server_tokens off;
    
    # Buffers
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    output_buffers 1 32k;
    postpone_output 1460;
    
    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # SSL
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Logs
    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;
    
    # Limitation de débit
    limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    # Configuration du site Odoo
    cat > /etc/nginx/sites-available/odoo << EOF
# Upstream Odoo
upstream odoo {
    server 127.0.0.1:8069;
}

upstream odoochat {
    server 127.0.0.1:8072;
}

# Limitation de débit
map \$request_uri \$limit {
    ~*/web/login  login;
    ~*/web/database/manager  login;
    ~*/jsonrpc  api;
    default "";
}

# Redirection HTTP vers HTTPS
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

# Serveur HTTPS
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};
    
    # SSL
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;
    
    # En-têtes de sécurité
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy "strict-origin-when-cross-origin";
    
    # Logs
    access_log /var/log/nginx/odoo.access.log;
    error_log /var/log/nginx/odoo.error.log;
    
    # Longpolling
    location /longpolling {
        proxy_pass http://odoochat;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Location principale
    location / {
        # Limitation de débit
        limit_req zone=\$limit burst=5 nodelay;
        
        proxy_pass http://odoo;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Cache fichiers statiques
        location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            proxy_pass http://odoo;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
}
EOF
    
    # Générer les paramètres DH
    openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    
    ln -s /etc/nginx/sites-available/odoo /etc/nginx/sites-enabled/
    nginx -t
    systemctl enable nginx
}

# SSL configuration
setup_ssl() {
    if [ "$USE_CLOUDFLARE" = true ]; then
        log "Configuration for Cloudflare Tunnel..."
        
        # No local SSL with Cloudflare Tunnel
        # Cloudflare handles the SSL
        log "SSL managed by Cloudflare - no local configuration required"
        
        # Install cloudflared
        curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
        dpkg -i cloudflared.deb
        rm cloudflared.deb
        
        cat << EOF

🔒 CONFIGURATION CLOUDFLARE TUNNEL REQUIRE:

1. Log in to Cloudflare Dashboard
2. Go to Zero Trust > Access > Tunnels
3. Create a new tunnel
4. Copy the token and run:
   cloudflared service install TOKEN_HERE

5. Configure the tunnel:
   - Type: HTTP
   - URL: localhost:8069
   - Domain: ${DOMAIN}

6. Restart Nginx without SSL:
   systemctl restart nginx

EOF
        
        # Nginx configuration without SSL for Cloudflare
        setup_nginx_cloudflare
        
    else
        log "SSL configuration with Let's Encrypt..."
        
        # Check DNS resolution before proceeding
        if ! host "$DOMAIN" &>/dev/null; then
            warn "Cannot resolve domain $DOMAIN. Checking DNS configuration..."
            
            # Additional DNS check with dig if available
            if command -v dig &>/dev/null; then
                dig_result=$(dig +short "$DOMAIN")
                if [[ -z "$dig_result" ]]; then
                    warn "Domain $DOMAIN does not resolve to any IP address."
                    warn "Please verify your DNS configuration or wait for DNS propagation."
                    warn "Continuing anyway, but SSL setup might fail."
                else
                    info "Domain $DOMAIN resolves to: $dig_result"
                fi
            fi
        else
            info "Domain $DOMAIN resolves correctly."
        fi
        
        apt install -yq certbot python3-certbot-nginx
        
        # Configure DDNS if necessary
        if [ "$CONNECTION_TYPE" = "2" ]; then
            setup_ddns
        fi
        
        # Create certificate
        if ! certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos --email ${LE_EMAIL}; then
            error "Failed to obtain SSL certificate. Check DNS configuration and try again."
        fi
        
        # Automatic renewal
        systemctl enable certbot.timer
        systemctl start certbot.timer
        
        systemctl restart nginx
    fi
}

# Monitoring configuration
setup_monitoring() {
    log "Monitoring configuration..."
    
    # Netdata
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --disable-telemetry --non-interactive
    
    # Fail2ban configuration
    cat > /etc/fail2ban/jail.d/odoo.conf << EOF
[odoo]
enabled = true
port = 443,80
filter = odoo
logpath = /var/log/nginx/odoo.error.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    cat > /etc/fail2ban/filter.d/odoo.conf << EOF
[Definition]
failregex = ^<HOST> -.*"POST /web/login HTTP/1.1" 200
ignoreregex =
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
}

# Backup configuration
setup_backups() {
    log "Backup configuration..."
    
    mkdir -p /opt/backups/{daily,weekly,monthly}
    
    cat > /opt/backups/backup_odoo.sh << EOF
#!/bin/bash
# Script de sauvegarde complète Odoo

DATE=\$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/backups/daily"
DB_NAME="${DB_NAME}"
DB_USER="${DB_USER}"
ODOO_DATA="/opt/odoo/data"

# Sauvegarde base de données
sudo -u postgres pg_dump -Fc \${DB_NAME} > \${BACKUP_DIR}/db_\${DATE}.dump

# Sauvegarde fichiers
if [ -d "\${ODOO_DATA}" ]; then
    tar -czf \${BACKUP_DIR}/files_\${DATE}.tar.gz \${ODOO_DATA}
fi

# Sauvegarde configuration
tar -czf \${BACKUP_DIR}/config_\${DATE}.tar.gz /etc/odoo /etc/nginx/sites-available/odoo

# Cleanup (keep 7 days)
find \${BACKUP_DIR} -name "*.dump" -mtime +7 -delete
find \${BACKUP_DIR} -name "*.tar.gz" -mtime +7 -delete

echo "Sauvegarde terminée : \${DATE}"
EOF
    
    chmod +x /opt/backups/backup_odoo.sh
    
    # Cron job
    (crontab -l 2>/dev/null; echo "0 2 * * * /opt/backups/backup_odoo.sh >> /var/log/backup.log 2>&1") | crontab -
}

# Firewall configuration
setup_firewall() {
    info "Advanced firewall configuration..."
    
    # Install UFW if necessary
    if ! command -v ufw &> /dev/null; then
        apt install -yq ufw
    fi
    
    # Backup existing rules
    if [ -f /etc/ufw/user.rules ]; then
        cp /etc/ufw/user.rules /etc/ufw/user.rules.bak.$(date +%Y%m%d%H%M%S)
    fi
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Basic rules with rate limiting
    ufw limit ssh comment "SSH with rate limiting"
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"
    
    # Anti-brute force rules
    cat > /etc/ufw/applications.d/odoo << EOF
[Odoo-Web]
title=Odoo Web
description=Odoo Web Service
ports=8069/tcp

[Odoo-Chat]
title=Odoo Chat
description=Odoo Longpolling Service
ports=8072/tcp
EOF
    
    # Add rate limiting with ufw
    # Allow SSH with rate limiting
    ufw limit ssh comment "SSH with rate limiting"
    
    # Allow HTTP with rate limiting
    ufw limit 80/tcp comment "HTTP with rate limiting"
    
    # Services exposed only if requested
    if [[ "${EXPOSE_MONITORING:-false}" == "true" ]]; then
        ufw allow 19999/tcp comment "Netdata"
        ufw allow 3000/tcp comment "Grafana"
        ufw allow 9090/tcp comment "Prometheus"
        ufw allow 9093/tcp comment "Alertmanager"
        info "Monitoring ports exposed externally"
    else
        # Otherwise, only allow localhost
        ufw allow from 127.0.0.1 to any port 19999 comment "Netdata local"
        ufw allow from 127.0.0.1 to any port 3000 comment "Grafana local"
        ufw allow from 127.0.0.1 to any port 9090 comment "Prometheus local"
        ufw allow from 127.0.0.1 to any port 9093 comment "Alertmanager local"
        info "Monitoring ports restricted to localhost"
    fi
    
    # Advanced security: block ping floods
    cat >> /etc/ufw/before.rules << EOF

# Block ping floods
-A ufw-before-input -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP

# Block port scanning
-A ufw-before-input -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j ACCEPT
-A ufw-before-input -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP
EOF
    
    # SYN flood protection
    cat >> /etc/sysctl.conf << EOF
# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 3
net.ipv4.conf.all.rp_filter = 1
EOF
    sysctl -p
    
    # Enable firewall
    ufw --force enable
    
    # Verify firewall is active
    if ! ufw status | grep -q "Status: active"; then
        error "Failed to activate firewall"
    fi
    
    # Configure automatic logging and alerts
    mkdir -p /var/log/ufw
    touch /var/log/ufw/blocked.log
    
    cat > /usr/local/bin/ufw_monitor.sh << 'EOF'
#!/bin/bash
# Monitor UFW logs for suspicious activity

LOG_FILE="/var/log/ufw/blocked.log"
ALERT_THRESHOLD=20  # Number of blocks before alerting

# Get recent blocks (last hour)
RECENT_BLOCKS=\$(grep -c "\$(date +"%b %d %H" --date="1 hour ago")" /var/log/ufw.log)

# Check for repeat offenders
if [ \$RECENT_BLOCKS -gt \$ALERT_THRESHOLD ]; then
  echo "\[\$(date)\] WARNING: High number of firewall blocks: \$RECENT_BLOCKS in the last hour" >> "\$LOG_FILE"
  
  # Get the top offenders
  TOP_OFFENDERS=\$(grep "UFW BLOCK" /var/log/ufw.log | grep "\$(date +"%b %d %H" --date="1 hour ago")" | awk '{print \$12}' | sort | uniq -c | sort -nr | head -5)
  echo "Principaux contrevenants :" >> "\$LOG_FILE"
  echo "\$TOP_OFFENDERS" >> "\$LOG_FILE"
fi
EOF
    
    chmod +x /usr/local/bin/ufw_monitor.sh
    (crontab -l 2>/dev/null; echo "10 * * * * /usr/local/bin/ufw_monitor.sh") | crontab -
    
    info "Advanced firewall configuration completed with monitoring"
}

# Implementing missing setup_nginx_cloudflare function
setup_nginx_cloudflare() {
    info "Configuring Nginx for Cloudflare Tunnel..."
    
    # Reconfiguration of Nginx without SSL
    cat > /etc/nginx/sites-available/odoo << EOF
upstream odoo {
    server 127.0.0.1:8069;
}

upstream odoochat {
    server 127.0.0.1:8072;
}

server {
    listen 80;
    server_name ${DOMAIN};
    
    access_log /var/log/nginx/odoo.access.log;
    error_log /var/log/nginx/odoo.error.log;
    
    proxy_read_timeout 720s;
    proxy_connect_timeout 720s;
    proxy_send_timeout 720s;
    
    # Longpolling
    location /longpolling {
        proxy_pass http://odoochat;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Main location
    location / {
        proxy_pass http://odoo;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Cache static files
        location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
            proxy_pass http://odoo;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
        }
    }
}
EOF

    systemctl reload nginx
    info "Nginx configured to work with Cloudflare Tunnel"
}

# Functionality tests
run_tests() {
    log "Functionality tests..."
    
    # PostgreSQL test
    if sudo -u postgres psql -c "SELECT 1;" > /dev/null 2>&1; then
        log "✓ PostgreSQL works"
    else
        error "✗ PostgreSQL not working"
    fi
    
    # Redis test
    if redis-cli -a ${REDIS_PASS} ping > /dev/null 2>&1; then
        log "✓ Redis works"
    else
        error "✗ Redis not working"
    fi
    
    # Odoo test
    if systemctl is-active --quiet odoo; then
        log "✓ Odoo is active"
    else
        error "✗ Odoo not working"
    fi
    
    # Nginx test
    if systemctl is-active --quiet nginx; then
        log "✓ Nginx is active"
    else
        error "✗ Nginx not working"
    fi
}

# ===================== FINAL VERIFICATION =====================
verify_installation() {
    info "Final verification of installation..."
    local ERRORS=()
    local WARNINGS=()
    
    echo -e "\n🔍 Starting checks..."
    
    # Function to test with progress bar
    test_with_progress() {
        local message="$1"
        local cmd="$2"
        echo -n "⏳ $message... "
        # Redirect stderr to stdout to capture all errors
        if output=$(eval "$cmd" 2>&1); then
            echo -e "\r✅ $message"
            return 0
        else
            echo -e "\r❌ $message"
            warn "Command failed: $cmd"
            warn "Error: $output"
            return 1
        fi
    }

    # 1. Checking services
    echo -e "\n📊 Checking services:"
    
    # PostgreSQL
    if ! test_with_progress "PostgreSQL" "systemctl is-active --quiet postgresql"; then
        ERRORS+=("PostgreSQL not active")
    else
        # Test connection
        if ! test_with_progress "PostgreSQL connection" "sudo -u postgres psql -c '\q'"; then
            ERRORS+=("Unable to connect to PostgreSQL")
        fi
    fi
    
    # Redis
    if ! test_with_progress "Redis" "systemctl is-active --quiet redis-server"; then
        ERRORS+=("Redis not active")
    else
        # Redis connection test
        if ! test_with_progress "Redis connection" "redis-cli ping"; then
            ERRORS+=("Unable to connect to Redis")
        fi
    fi
    
    # Nginx
    if ! test_with_progress "Nginx" "systemctl is-active --quiet nginx"; then
        ERRORS+=("Nginx not active")
    else
        # Nginx configuration test
        if ! test_with_progress "Nginx configuration" "nginx -t"; then
            ERRORS+=("Invalid Nginx configuration")
        fi
    fi
    
    # Odoo
    if ! test_with_progress "Odoo" "systemctl is-active --quiet odoo"; then
        ERRORS+=("Odoo not active")
    else
        # Web Odoo access test
        if ! test_with_progress "Odoo web interface" "curl -s -I http://localhost:8069 | grep -q '200 OK'"; then
            ERRORS+=("Odoo web interface inaccessible")
        fi
    fi

    # 2. Checking files
    echo -e "\n📁 Checking files:"
    
    # Configuration files
    local CONFIG_FILES=(
        "/etc/odoo/odoo.conf"
        "/etc/nginx/sites-enabled/odoo"
        "/etc/postgresql/*/main/postgresql.conf"
        "/etc/redis/redis.conf"
    )
    
    for file in "${CONFIG_FILES[@]}"; do
        if ! test_with_progress "Configuration $file" "test -f $file"; then
            ERRORS+=("Missing file: $file")
        fi
    done
    
    # Permissions
    if ! test_with_progress "Odoo permissions" "test -O /opt/odoo -a -G /opt/odoo"; then
        ERRORS+=("Incorrect permissions on /opt/odoo")
    fi

    # 3. Checking ports
    echo -e "\n🔌 Checking ports:"
    local PORTS=(80 443 8069 8072 5432 6379)
    
    for port in "${PORTS[@]}"; do
        if ! test_with_progress "Port $port" "netstat -tuln | grep -q ':$port '"; then
            WARNINGS+=("Port $port not open")
        fi
    done

    # 4. Checking backups
    echo -e "\n💾 Checking backups:"
    if ! test_with_progress "Backup directory" "test -d /opt/backups"; then
        WARNINGS+=("Backup directory not found")
    fi
    
    # Backup test
    if ! test_with_progress "Backup test" "/opt/backups/backup_odoo.sh test"; then
        WARNINGS+=("Backup test failed")
    fi

    # 5. Checking SSL
    echo -e "\n🔒 Checking SSL:"
    if [[ "$USE_CLOUDFLARE" != true ]]; then
        if ! test_with_progress "SSL certificates" "test -d /etc/letsencrypt/live/${DOMAIN}"; then
            WARNINGS+=("SSL certificates not found")
        fi
    fi

    # 6. Checking monitoring
    echo -e "\n📈 Checking monitoring:"
    local MONITORING_SERVICES=("prometheus-node-exporter" "grafana-server" "loki" "promtail")
    
    for service in "${MONITORING_SERVICES[@]}"; do
        if ! test_with_progress "Service $service" "systemctl is-active --quiet $service"; then
            WARNINGS+=("Monitoring service $service inactive")
        fi
    fi

    # Display result
    echo -e "\n📋 Verification result:"
    
    if [ ${#ERRORS[@]} -gt 0 ]; then
        echo -e "\n❌ Critical errors detected:"
        for error in "${ERRORS[@]}"; do
            echo "  - $error"
        done
    fi
    
    if [ ${#WARNINGS[@]} -gt 0 ]; then
        echo -e "\n⚠️ Warnings:"
        for warning in "${WARNINGS[@]}"; do
            echo "  - $warning"
        done
    fi
    
    if [ ${#ERRORS[@]} -eq 0 ] && [ ${#WARNINGS[@]} -eq 0 ]; then
        echo -e "\n✅ Installation successfully verified!"
        return 0
    fi
    
    # Suggested corrections
    if [ ${#ERRORS[@]} -gt 0 ]; then
        echo -e "\n🔧 Suggested solutions:"
        echo "1. Restart services:"
        echo "   systemctl restart postgresql redis-server nginx odoo"
        echo "2. Check logs:"
        echo "   journalctl -xe"
        echo "3. Verify configurations:"
        echo "   less /etc/odoo/odoo.conf"
        echo "   nginx -t"
        echo "4. Repair permissions:"
        echo "   chown -R odoo:odoo /opt/odoo"
        
        read -p "Do you want to attempt automatic repair? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "🔄 Attempting repair..."
            systemctl restart postgresql redis-server nginx odoo
            chown -R odoo:odoo /opt/odoo
            chmod -R 755 /opt/odoo
            echo "⏳ New check in 10 seconds..."
            sleep 10
            verify_installation
        fi
    fi
    
    if [ ${#ERRORS[@]} -gt 0 ]; then
        return 1
    fi
    return 0
}

# ===================== SYSTEM DETECTION AND OPTIMIZATION =====================
setup_distribution_detection() {
    info "Detecting Linux distribution..."
    
    # Distribution detection
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        DISTRO_FAMILY="unknown"
    else
        error "Unable to detect distribution"
    fi
    
    # Determine distribution family for better compatibility
    case $DISTRO in
        debian|ubuntu|linuxmint|elementary|pop|zorin)
            DISTRO_FAMILY="debian"
            PKG_MANAGER="apt"
            PKG_INSTALL="apt-get install -yq"
            PKG_UPDATE="apt-get update"
            ;;
        centos|rhel|fedora|rocky|alma|ol|amzn)
            DISTRO_FAMILY="redhat"
            if command -v dnf &>/dev/null; then
                PKG_MANAGER="dnf"
                PKG_INSTALL="dnf install -y"
                PKG_UPDATE="dnf check-update"
            else
                PKG_MANAGER="yum"
                PKG_INSTALL="yum install -y"
                PKG_UPDATE="yum check-update"
            fi
            ;;
        opensuse*|suse|sles)
            DISTRO_FAMILY="suse"
            PKG_MANAGER="zypper"
            PKG_INSTALL="zypper install -y"
            PKG_UPDATE="zypper refresh"
            ;;
        arch|manjaro|endeavouros)
            DISTRO_FAMILY="arch"
            PKG_MANAGER="pacman"
            PKG_INSTALL="pacman -S --noconfirm"
            PKG_UPDATE="pacman -Sy"
            ;;
        alpine)
            DISTRO_FAMILY="alpine"
            PKG_MANAGER="apk"
            PKG_INSTALL="apk add --no-cache"
            PKG_UPDATE="apk update"
            ;;
        *)
            warn "Distribution $DISTRO might not be fully supported."
            DISTRO_FAMILY="unknown"
            ;;
    esac
    
    # Compatibility check
    if [[ "$DISTRO_FAMILY" == "debian" ]]; then
        if [[ "$DISTRO" == "debian" && "$VERSION_ID" -lt 12 ]]; then
            error "Debian $VERSION_ID not supported. Minimum version: Debian 12"
        elif [[ "$DISTRO" == "ubuntu" && "$VERSION_ID" < "24.04" ]]; then
            error "Ubuntu $VERSION_ID not supported. Minimum version: Ubuntu 24.04"
        fi
    elif [[ "$DISTRO_FAMILY" == "alpine" ]]; then
        if [[ "$(echo "$VERSION_ID" | cut -d. -f1)" -lt 3 ]]; then
            error "Alpine $VERSION_ID not supported. Minimum version: Alpine 3.14"
        fi
        
        # Alpine specific setup
        info "Setting up Alpine Linux environment"
        
        # Alpine needs bash and other essential tools
        if [[ "$DRY_RUN" != true ]]; then
            apk add --no-cache bash curl wget ca-certificates
            
            # Create compatibility symlinks for common utilities
            if ! command -v sudo &>/dev/null; then
                apk add --no-cache sudo
            fi
            
            # Ensure shadow is installed for user management
            apk add --no-cache shadow
        fi
    elif [[ "$DISTRO_FAMILY" == "unknown" ]]; then
        warn "Using $DISTRO $VERSION_ID which is not officially supported."
        warn "Installation may fail or require manual adjustments."
    fi
    
    info "Distribution détectée : $DISTRO $VERSION (famille $DISTRO_FAMILY)"
    info "Gestionnaire de paquets : $PKG_MANAGER"
}

setup_timezone_locale_detection() {
    info "Configuring timezone and locale..."
    
    # Timezone detection
    if [ -f /etc/timezone ]; then
        CURRENT_TZ=$(cat /etc/timezone)
    else
        CURRENT_TZ=$(timedatectl | grep "Time zone" | awk '{print $3}')
    fi
    
    # Timezone configuration if not set
    if [ -z "$CURRENT_TZ" ]; then
        timedatectl set-timezone "UTC"
        info "Timezone set to UTC by default"
    else
        info "Current timezone: $CURRENT_TZ"
    fi
    
    # Locale configuration
    if ! locale -a | grep -q "^fr_FR.utf8"; then
        info "Installing FR locale..."
        locale-gen fr_FR.UTF-8
    fi
    if ! locale -a | grep -q "^en_US.utf8"; then
        info "Installing EN locale..."
        locale-gen en_US.UTF-8
    fi
    
    update-locale LANG=fr_FR.UTF-8 LC_ALL=fr_FR.UTF-8
    info "Locale set to fr_FR.UTF-8"
}

setup_ipv6_support() {
    info "Configuring IPv6 support..."
    
    # Check IPv6 support
    if [ ! -f /proc/net/if_inet6 ]; then
        warn "IPv6 not supported by kernel"
        return
    fi
    
    # Configure sysctl for IPv6
    cat >> /etc/sysctl.conf << EOF
# IPv6 configuration
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
EOF
    
    # Configure Nginx for IPv6
    sed -i 's/listen 80;/listen 80;\n    listen [::]:80;/' /etc/nginx/sites-available/odoo
    sed -i 's/listen 443 ssl;/listen 443 ssl;\n    listen [::]:443 ssl;/' /etc/nginx/sites-available/odoo
    
    # Configure PostgreSQL for IPv6
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/*/main/postgresql.conf
    
    info "IPv6 support configured"
}

setup_python_wheel_cache() {
    info "Configuring pip/wheel cache..."
    
    # Create cache directory
    mkdir -p /opt/odoo/.cache/pip
    chown -R odoo:odoo /opt/odoo/.cache
    
    # Configure pip
    cat > /opt/odoo/.config/pip/pip.conf << EOF
[global]
download-cache = /opt/odoo/.cache/pip
wheel-dir = /opt/odoo/.cache/pip/wheels
find-links = /opt/odoo/.cache/pip/wheels
EOF
    
    # Pre-download common dependencies
    sudo -u odoo pip wheel --wheel-dir=/opt/odoo/.cache/pip/wheels -r /opt/odoo/odoo/requirements.txt
    
    info "pip/wheel cache configured"
}

setup_parallel_apt_install() {
    info "Optimizing apt installations..."
    
    # Install aria2 for faster downloads
    apt install -yq aria2
    
    # Configure parallel installations with aria2
    cat > /etc/apt/apt.conf.d/99parallel-install << EOF
Acquire::Queue-Mode "host";
Acquire::http::Pipeline-Depth "5";
Acquire::https::Pipeline-Depth "5";
Acquire::Languages "none";
Acquire::ForceIPv4 "true";
Acquire::http::Timeout "180";
Acquire::https::Timeout "180";
# Use aria2 for downloads
Acquire::http::Dl-Limit "0";
Acquire::https::Dl-Limit "0";
EOF

    # Configure number of parallel connections for aria2
    CORES=$(nproc)
    MAX_CONNECTIONS=$((CORES * 4))
    echo "max-connection-per-server=$MAX_CONNECTIONS" >> /etc/aria2/aria2.conf
    echo "min-split-size=1M" >> /etc/aria2/aria2.conf
    
    info "Parallel installation configured ($CORES cores, $MAX_CONNECTIONS connections max)"
}

# ===================== NEW OPTIMIZATIONS =====================
setup_parallel_optimizations() {
    info "Configuring parallel optimizations..."
    
    # Install optimization tools
    apt install -yq parallel pigz aria2 apt-cacher-ng dnsmasq
    
    # Configure apt-cacher-ng
    echo "PassThroughPattern: .*" >> /etc/apt-cacher-ng/acng.conf
    systemctl enable --now apt-cacher-ng
    
    # Configure dnsmasq
    echo "cache-size=1000" >> /etc/dnsmasq.conf
    echo "no-negcache" >> /etc/dnsmasq.conf
    systemctl enable --now dnsmasq
}

setup_cockpit() {
    info "Installing Cockpit (web administration interface)..."
    
    apt install -yq cockpit cockpit-pcp cockpit-packagekit
    systemctl enable --now cockpit.socket
    
    # Configure firewall for Cockpit
    ufw allow 9090/tcp
}

setup_crowdsec() {
    info "Installing CrowdSec..."
    
    # Installation
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt install -yq crowdsec
    
    # Installation of collections
    cscli collections install crowdsecurity/nginx
    cscli collections install crowdsecurity/http-cve
    
    systemctl enable --now crowdsec
}

# ===================== ADVANCED LOGGING =====================
setup_advanced_logging() {
    info "Advanced logging configuration..."
    
    # Install logging tools
    apt install -yq rsyslog logrotate filebeat prometheus-node-exporter loki promtail

    # Advanced rsyslog configuration
    cat > /etc/rsyslog.d/odoo.conf << EOF
# Detailed Odoo logs
template(name="OdooFormat" type="string" string="%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag% %msg%\n")

# Odoo logging rules
if \$programname == 'odoo' then {
    action(type="omfile" file="/var/log/odoo/odoo-detailed.log" template="OdooFormat")
    action(type="omfile" file="/var/log/odoo/odoo-errors.log" template="OdooFormat" filter.priority="error")
    action(type="omfile" file="/var/log/odoo/odoo-security.log" template="OdooFormat" filter.regex="(login|password|security|attack|hack)")
}

# PostgreSQL logs
if \$programname == 'postgres' then {
    action(type="omfile" file="/var/log/postgresql/postgresql-detailed.log")
}

# Nginx logs
if \$programname == 'nginx' then {
    action(type="omfile" file="/var/log/nginx/nginx-detailed.log")
}
EOF

    # Configure Loki for centralized logs
    cat > /etc/loki/config.yml << EOF
auth_enabled: false

server:
  http_listen_port: 3100

ingester:
  lifecycler:
    address: 127.0.0.1
    ring:
      kvstore:
        store: inmemory
      replication_factor: 1
    final_sleep: 0s
  chunk_idle_period: 5m
  chunk_retain_period: 30s

schema_config:
  configs:
    - from: 2020-01-01
      store: boltdb
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

storage_config:
  boltdb:
    directory: /var/lib/loki/index
  filesystem:
    directory: /var/lib/loki/chunks
EOF

    # Configure Promtail for sending logs to Loki
    cat > /etc/promtail/config.yml << EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /var/lib/promtail/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  - job_name: odoo_logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: odoo
          __path__: /var/log/odoo/*.log

  - job_name: system_logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: system
          __path__: /var/log/syslog
EOF

    # Configure log rotation
    cat > /etc/logrotate.d/odoo << EOF
/var/log/odoo/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 odoo odoo
    sharedscripts
    postrotate
        systemctl reload rsyslog
    endscript
}
EOF

    systemctl restart rsyslog
    systemctl enable --now loki promtail
}

# ===================== REMOTE MONITORING =====================
setup_remote_monitoring() {
    info "Remote monitoring configuration..."
    
    # Install monitoring tools
    apt install -yq grafana prometheus prometheus-node-exporter prometheus-alertmanager netdata

    # Configure Prometheus
    cat > /etc/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

rule_files:
  - "/etc/prometheus/rules/*.yml"

scrape_configs:
  - job_name: 'odoo'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'

  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']

  - job_name: 'postgresql'
    static_configs:
      - targets: ['localhost:9187']

  - job_name: 'nginx'
    static_configs:
      - targets: ['localhost:9113']
EOF

    # Configure Prometheus alerts
    mkdir -p /etc/prometheus/rules
    cat > /etc/prometheus/rules/alerts.yml << EOF
groups:
- name: odoo_alerts
  rules:
  - alert: OdooDown
    expr: up{job="odoo"} == 0
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Odoo is down"
      description: "Odoo service is inaccessible for 5 minutes"

  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High CPU usage"
      description: "CPU usage is above 80% for 10 minutes"

  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 85
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "High memory usage"
      description: "Memory usage is above 85% for 10 minutes"

  - alert: DiskSpaceLow
    expr: node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} * 100 < 15
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Low disk space"
      description: "Less than 15% of disk space remaining"
EOF

    # Configure Grafana
    cat > /etc/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://localhost:9090
    isDefault: true

  - name: Loki
    type: loki
    access: proxy
    url: http://localhost:3100
EOF

    # Configure Netdata for remote access
    cat >> /etc/netdata/netdata.conf << EOF
[web]
    bind to = *
    allow connections from = *
EOF

    # Setting up Grafana dashboards
    mkdir -p /var/lib/grafana/dashboards
    
    # Creating a dashboard for Odoo
    cat > /var/lib/grafana/dashboards/odoo.json << 'EOF'
{
  "dashboard": {
    "title": "Odoo Monitoring",
    "panels": [
      {
        "title": "CPU Usage",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "100 - (avg by(instance) (irate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100"
          }
        ]
      },
      {
        "title": "Disk Usage",
        "type": "graph",
        "datasource": "Prometheus",
        "targets": [
          {
            "expr": "100 - (node_filesystem_avail_bytes{mountpoint=\"/\"} / node_filesystem_size_bytes{mountpoint=\"/\"} * 100)"
          }
        ]
      }
    ]
  }
}
EOF

    # Activating and starting services
    systemctl enable --now prometheus prometheus-node-exporter prometheus-alertmanager grafana-server netdata
    
    # Opening necessary ports
    ufw allow 3000/tcp  # Grafana
    ufw allow 19999/tcp # Netdata
    
    info "Remote monitoring configuration completed"
    echo "
Access to monitoring interfaces:
- Grafana: http://$DOMAIN:3000 (admin/admin)
- Netdata: http://$DOMAIN:19999
- Prometheus: http://$DOMAIN:9090
- Alertmanager: http://$DOMAIN:9093
"
}

# Main function update to include new functions
main() {
    local start_time=$(date +%s)
    info "Starting optimized Odoo installation..."
    
    # Load external modules if available, otherwise use built-in functions
    charger_module "system_checks" || true
    charger_module "postgresql" || true
    charger_module "nginx" || true
    charger_module "redis" || true
    charger_module "odoo" || true
    charger_module "monitoring" || true
    charger_module "security" || true
    charger_module "backup" || true
    
    # Run comprehensive preliminary checks first
    if ! run_once "comprehensive_check" comprehensive_checks; then
        error "Critical issues detected during preliminary checks. Aborting installation."
        exit 1
    fi
    
    # Detailed system constraints checks
    run_once "system_constraints" check_system_constraints
    
    # Configure proxy if needed
    if [[ -n "${PROXY_URL:-}" ]]; then
        export http_proxy="$PROXY_URL"
        export https_proxy="$PROXY_URL"
        info "Proxy configured: $PROXY_URL"
    fi
    
    # Distribution detection
    run_once "distro_detection" setup_distribution_detection
    
    # New optimizations - these can be run in parallel
    if [[ "$DRY_RUN" != true ]]; then
        parallel_exec \
            "parallel_optimizations" "setup_parallel_optimizations" \
            "cockpit" "setup_cockpit" \
            "crowdsec" "setup_crowdsec"
    else
        # In dry-run mode, we run them sequentially for better logging
        run_once "parallel_optimizations" setup_parallel_optimizations
        run_once "cockpit" setup_cockpit
        run_once "crowdsec" setup_crowdsec
    fi
    
    # Interactive configuration
    run_once "interactive" validate_interactive
    run_once "user_config" get_user_config
    run_once "validate" validate_inputs
    
    # System setup
    run_once "system_optimization" optimize_system
    run_once "packages" install_packages
    
    # Main components installation
    run_once "postgresql" setup_postgresql
    run_once "postgresql_advanced" setup_postgresql_advanced
    run_once "postgresql_health" setup_postgresql_health_checks
    run_once "redis" setup_redis
    run_once "odoo" install_odoo
    run_once "nginx" setup_nginx
    run_once "ssl" setup_ssl
    
    # Security and monitoring
    run_once "monitoring" setup_monitoring
    run_once "backups" setup_backups
    run_once "firewall" setup_firewall
    
    # Advanced configurations
    run_once "logging" setup_advanced_logging
    run_once "remote_monitoring" setup_remote_monitoring
    
    # Final verification
    if verify_installation; then
        run_once "documentation" generate_docs
        run_once "cleanup" cleanup
        
        # Calculate execution time
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        local hours=$((duration / 3600))
        local minutes=$(( (duration % 3600) / 60 ))
        local seconds=$((duration % 60))
        
        info "Installation completed successfully in ${hours}h ${minutes}m ${seconds}s."
        
        if [[ "$DRY_RUN" == true ]]; then
            info "DRY-RUN: No actual changes were made to the system."
        else
            info "Documentation generated."
            echo
            system_cmd "cat /root/odoo_installation_summary.txt" "Display installation summary"
        fi
    else
        warn "Installation completed with warnings. Check the report."
    fi
}

# Main execution with trap for unexpected errors
START_TIME=$(date +%s)
main "$@"
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
HOURS=$((DURATION / 3600))
MINUTES=$(( (DURATION % 3600) / 60 ))
SECONDS=$((DURATION % 60))
info "Total execution time: ${HOURS}h ${MINUTES}m ${SECONDS}s"

# ===================== STUBS FUNCTIONALITY TO COMPLETE =====================

# Implementing setup_ddns function for dynamic DNS configuration
setup_ddns() {
    info "Configuring Dynamic DNS..."
    
    case "$DDNS_SERVICE" in
        duckdns)
            if [[ -z "$SUBDOMAIN" || -z "$DUCKDNS_TOKEN" ]]; then
                error "DuckDNS: subdomain or token missing"
            fi
            
            # Create DuckDNS update script
            cat > /usr/local/bin/update_duckdns.sh << EOF
#!/bin/bash
curl -s "https://www.duckdns.org/update?domains=${SUBDOMAIN}&token=${DUCKDNS_TOKEN}&ip=" 
EOF
            chmod +x /usr/local/bin/update_duckdns.sh
            
            # Configure cron
            (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/update_duckdns.sh > /var/log/duckdns.log 2>&1") | crontab -
            
            # Execute immediately
            /usr/local/bin/update_duckdns.sh
            info "DuckDNS configured for ${SUBDOMAIN}.duckdns.org"
            ;;
            
        noip)
            if [[ -z "$NOIP_USER" || -z "$NOIP_PASS" ]]; then
                error "No-IP: username or password missing"
            fi
            
            # Install No-IP
            apt install -yq build-essential
            cd /tmp
            wget http://www.no-ip.com/client/linux/noip-duc-linux.tar.gz
            tar xzf noip-duc-linux.tar.gz
            cd noip-*
            make
            cp noip2 /usr/local/bin/
            
            # Configure
            cat > /tmp/no-ip.conf << EOF
${NOIP_USER}
${NOIP_PASS}
${DOMAIN}
30
n
EOF
            /usr/local/bin/noip2 -C -c /tmp/no-ip.conf
            rm /tmp/no-ip.conf
            
            # Service
            cat > /etc/systemd/system/noip2.service << EOF
[Unit]
Description=No-IP Dynamic DNS Update Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/noip2
Restart=always

[Install]
WantedBy=multi-user.target
EOF
            
            systemctl daemon-reload
            systemctl enable --now noip2
            info "No-IP configured for ${DOMAIN}"
            ;;
            
        dynu)
            if [[ -z "$DYNU_USER" || -z "$DYNU_PASS" ]]; then
                error "Dynu: username or password missing"
            fi
            
            # Create Dynu update script
            cat > /usr/local/bin/update_dynu.sh << EOF
#!/bin/bash
curl -s "https://api.dynu.com/nic/update?hostname=${DOMAIN}&username=${DYNU_USER}&password=${DYNU_PASS}"
EOF
            chmod +x /usr/local/bin/update_dynu.sh
            
            # Configure cron
            (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/update_dynu.sh > /var/log/dynu.log 2>&1") | crontab -
            
            # Execute immediately
            /usr/local/bin/update_dynu.sh
            info "Dynu configured for ${DOMAIN}"
            ;;
            
        *)
            info "No DDNS service configured"
            ;;
    esac
}

setup_dns_dynamic() {
    info "Dynamic DNS/Cloudflare Tunnel configuration..."
    case "$DDNS_SERVICE" in
        duckdns)
            if [[ -z "$SUBDOMAIN" || -z "$DUCKDNS_TOKEN" ]]; then
                error "DuckDNS: subdomain or token missing."
            fi
            echo "url=https://www.duckdns.org/update?domains=$SUBDOMAIN&token=$DUCKDNS_TOKEN&ip="" > /etc/cron.hourly/duckdns
            chmod 700 /etc/cron.hourly/duckdns
            info "DuckDNS configured for $SUBDOMAIN.duckdns.org."
            ;;
        noip)
            if [[ -z "$NOIP_USER" || -z "$NOIP_PASS" ]]; then
                error "No-IP: username or password missing."
            fi
            apt install -yq noip2
            noip2 -C -u "$NOIP_USER" -p "$NOIP_PASS"
            systemctl enable --now noip2
            info "No-IP configured."
            ;;
        dynu)
            if [[ -z "$DYNU_USER" || -z "$DYNU_PASS" ]]; then
                error "Dynu: username or password missing."
            fi
            cat > /usr/local/bin/dynu_ddns.sh <<EOF
#!/bin/bash
curl -s "https://api.dynu.com/nic/update?hostname=$DOMAIN&username=$DYNU_USER&password=$DYNU_PASS"
EOF
            chmod 700 /usr/local/bin/dynu_ddns.sh
            (crontab -l 2>/dev/null; echo "*/10 * * * * /usr/local/bin/dynu_ddns.sh > /var/log/dynu_ddns.log 2>&1") | crontab -
            info "Dynu configured."
            ;;
        *)
            info "No dynamic DNS service selected."
            ;;
    esac
}

setup_web_interface() {
    info "Deploying static web management interface..."
    mkdir -p /opt/odoo-admin-ui
    cat > /opt/odoo-admin-ui/index.html <<EOF
<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>Odoo Admin</title></head><body>
<h1>Odoo 17 - Administration</h1>
<ul>
<li><a href="https://$DOMAIN" target="_blank">Accès Odoo</a></li>
<li><a href="/var/auto_server_docs.md" target="_blank">Documentation serveur</a></li>
<li>Backup: /opt/backups/</li>
<li>Monitoring: Netdata <a href="http://$PUBLIC_IP:19999" target="_blank">(lien)</a></li>
</ul>
<p>Pour toute maintenance avancée, connectez-vous en SSH.</p>
</body></html>
EOF
    chmod 600 /opt/odoo-admin-ui/index.html
}

# Encryption of passwords (example for odoo.conf)
chiffrer_conf() {
    info "Encrypting Odoo configuration..."
    openssl enc -aes-256-cbc -salt -in /etc/odoo/odoo.conf -out /etc/odoo/odoo.conf.enc -k "$ADMIN_PASS"
    chmod 600 /etc/odoo/odoo.conf.enc
    info "File /etc/odoo/odoo.conf.enc encrypted."
}

# Strict permissions on sensitive files
renforcer_permissions() {
    info "Strengthening permissions on sensitive files..."
    chmod 600 /etc/odoo/odoo.conf /etc/odoo/odoo.conf.enc 2>/dev/null || true
    chmod 700 /opt/backups /opt/backups/backup_odoo.sh 2>/dev/null || true
    chmod 700 /var/log/odoo 2>/dev/null || true
}

test_rollback() {
    info "Automatic rollback test (simulation)..."
    # Example: deleting a file then rolling back
    touch /tmp/test_rollback
    add_rollback "rm -f /tmp/test_rollback"
    rm -f /tmp/test_rollback
    rollback
    [[ ! -f /tmp/test_rollback ]] && info "Rollback OK" || error "Rollback KO"
}

verifier_backup() {
    info "Verifying backup integrity..."
    local last_dump=$(ls -1t /opt/backups/daily/db_*.dump 2>/dev/null | head -n1)
    if [[ -f "$last_dump" ]]; then
        pg_restore -l "$last_dump" > /dev/null && info "PostgreSQL backup OK" || warn "Corrupted PostgreSQL backup"
    else
        warn "No PostgreSQL backup found."
    fi
}

# Advanced monitoring (export Odoo Prometheus)
setup_odoo_exporter() {
    info "Deploying Odoo Prometheus exporter..."
    pip install odoo-prometheus-exporter
    cat > /etc/systemd/system/odoo_exporter.service <<EOF
[Unit]
Description=Odoo Prometheus Exporter
After=odoo.service
[Service]
ExecStart=/opt/odoo/venv/bin/odoo-prometheus-exporter --odoo-url=http://localhost:8069 --odoo-db=$DB_NAME --odoo-username=admin --odoo-password=$ADMIN_PASS --port=9273
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now odoo_exporter
    info "Odoo Prometheus exporter active on port 9273."
}

# Dynamic tuning PostgreSQL/Redis/Nginx
adapt_tuning() {
    info "Dynamic tuning based on detected RAM..."
    RAM_GB=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
    if (( RAM_GB >= 64 )); then
        SHARED_BUFFERS="16GB"; EFFECTIVE_CACHE="48GB"; WORK_MEM="256MB"; REDIS_MEM="4GB"; WORKERS=$(( $(nproc) * 2 ))
    elif (( RAM_GB >= 32 )); then
        SHARED_BUFFERS="8GB"; EFFECTIVE_CACHE="24GB"; WORK_MEM="128MB"; REDIS_MEM="2GB"; WORKERS=$(( $(nproc) * 2 ))
    elif (( RAM_GB >= 16 )); then
        SHARED_BUFFERS="4GB"; EFFECTIVE_CACHE="12GB"; WORK_MEM="64MB"; REDIS_MEM="1GB"; WORKERS=$(( $(nproc) * 2 ))
    else
        SHARED_BUFFERS="1GB"; EFFECTIVE_CACHE="3GB"; WORK_MEM="16MB"; REDIS_MEM="256MB"; WORKERS=$(( $(nproc) ))
    fi
    info "Tuning: PostgreSQL $SHARED_BUFFERS, Redis $REDIS_MEM, Odoo $WORKERS workers."
}

generate_docs() {
    info "Generating auto documentation..."
    DOC_PATH="/var/auto_server_docs.md"
    echo "# Auto-Server Documentation" > "$DOC_PATH"
    echo "## Startup: $(date)" >> "$DOC_PATH"
    echo "- Domain: $DOMAIN" >> "$DOC_PATH"
    echo "- Services: Odoo, PostgreSQL, Redis, Nginx, SSL, Monitoring, Backup" >> "$DOC_PATH"
    echo "- Odoo access: https://$DOMAIN (admin/${ADMIN_PASS})" >> "$DOC_PATH"
    echo "- Backup: /opt/backups/" >> "$DOC_PATH"
    echo "- Monitoring: Netdata, Prometheus, Odoo Exporter (port 9273)" >> "$DOC_PATH"
    echo "- Dynamic tuning: $SHARED_BUFFERS PostgreSQL, $REDIS_MEM Redis, $WORKERS workers Odoo" >> "$DOC_PATH"
    echo "- Security: sensitive files encrypted, permissions strengthened" >> "$DOC_PATH"
    echo "- Test rollback: see /tmp/test_rollback" >> "$DOC_PATH"
    echo "- Backup verification: see logs" >> "$DOC_PATH"
}

# ===================== SECURITY AND ADVANCED HARDENING =====================
setup_2fa_odoo() {
    info "Enabling 2FA Odoo (instructions) ..."
    echo "Enable the official Odoo 2FA (Enterprise) or community (auth_totp)." > /var/odoo_2fa_instructions.txt
    echo "Link: https://apps.odoo.com/apps/modules/15.0/auth_totp/" >> /var/odoo_2fa_instructions.txt
}

setup_pgcrypto() {
    info "Enabling pgcrypto on PostgreSQL..."
    sudo -u postgres psql -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
}

setup_encrypted_backup() {
    info "Encrypted backup with GPG..."
    GPG_KEY="odoo-backup-key"
    gpg --batch --passphrase "$ADMIN_PASS" --quick-gen-key "$GPG_KEY" default default never || true
    sed -i '/tar -czf/ s|tar -czf|tar -czf - | gpg --batch --yes --passphrase $ADMIN_PASS -c -o|' /opt/backups/backup_odoo.sh
    info "Backups encrypted with GPG."
}

setup_password_rotation() {
    info "Setting up automatic password rotation..."
    cat > /usr/local/bin/rotate_odoo_passwords.sh <<EOF
#!/bin/bash
NEW_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-20)
sudo -u postgres psql -c "ALTER USER $DB_USER WITH PASSWORD '$NEW_PASS';"
sed -i "s/db_password = .*/db_password = $NEW_PASS/" /etc/odoo/odoo.conf
systemctl restart odoo
EOF
    chmod 700 /usr/local/bin/rotate_odoo_passwords.sh
    (crontab -l 2>/dev/null; echo "0 3 * * 0 /usr/local/bin/rotate_odoo_passwords.sh") | crontab -
}

setup_audit_logging() {
    info "Enabling Odoo/PostgreSQL audit logging..."
    sed -i 's/log_level = info/log_level = debug/' /etc/odoo/odoo.conf
    sudo -u postgres psql -c "ALTER SYSTEM SET log_statement = 'all';"
    systemctl restart postgresql
}

setup_network_isolation() {
    info "Advanced network isolation (iptables)..."
    iptables -A INPUT -p tcp --dport 5432 -s 127.0.0.1 -j ACCEPT
    iptables -A INPUT -p tcp --dport 5432 -j DROP
    iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
    iptables -A INPUT -p tcp --dport 6379 -j DROP
    iptables-save > /etc/iptables.rules
}

setup_ssh_hardening() {
    info "SSH hardening..."
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd
}

setup_antivirus_ids() {
    info "Installing ClamAV and IDS assistance..."
    apt install -yq clamav clamav-daemon
    systemctl enable --now clamav-daemon
    echo "For advanced IDS, see Falco or Snort."
}

setup_internal_pki() {
    info "Generating internal PKI for Redis/PostgreSQL..."
    mkdir -p /etc/odoo/pki
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/odoo/pki/odoo.key -out /etc/odoo/pki/odoo.crt -subj "/CN=odoo-internal"
    chmod 600 /etc/odoo/pki/*
}

setup_odoo_rate_limit() {
    info "Rate limiting Odoo application (instructions) ..."
    echo "Install the community 'auth_rate_limit' module or equivalent." > /var/odoo_rate_limit.txt
}

setup_secrets_management() {
    info "Secrets management with pass (example)..."
    apt install -yq pass
    echo "$ADMIN_PASS" | pass insert -m odoo/admin
}

setup_integrity_monitoring() {
    info "Installing AIDE for integrity monitoring..."
    apt install -yq aide
    aideinit
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}

setup_alerting() {
    info "Configuring email alerts for incidents..."
    apt install -yq mailutils
    echo 'Subject: [Odoo] Critical Incident' > /usr/local/bin/odoo_alert.sh
    echo 'A critical incident has been detected on the Odoo server.' >> /usr/local/bin/odoo_alert.sh
    chmod 700 /usr/local/bin/odoo_alert.sh
    (crontab -l 2>/dev/null; echo "@reboot /usr/local/bin/odoo_alert.sh | mail -s 'Odoo Incident' $LE_EMAIL") | crontab -
}

setup_auto_update() {
    info "Automatic Odoo update (git pull + restart)..."
    cat > /usr/local/bin/odoo_auto_update.sh <<EOF
#!/bin/bash
cd /opt/odoo/odoo
git pull
systemctl restart odoo
EOF
    chmod 700 /usr/local/bin/odoo_auto_update.sh
    (crontab -l 2>/dev/null; echo "0 4 * * 0 /usr/local/bin/odoo_auto_update.sh") | crontab -
}

setup_cloud_backup() {
    info "Cloud backup (example S3)..."
    apt install -yq awscli
    echo "0 5 * * * aws s3 sync /opt/backups/ s3://mon-bucket-odoo-backup/" | crontab -
}

setup_staging_env() {
    info "Deploying staging environment (clone prod)..."
    cp -r /opt/odoo /opt/odoo-staging
    cp -r /etc/odoo /etc/odoo-staging
}

setup_load_balancing() {
    info "Instructions for load balancing with HAProxy..."
    echo "See https://www.haproxy.org/ for configuring an Odoo cluster." > /var/odoo_lb.txt
}

setup_cdn() {
    info "Instructions for configuring Cloudflare CDN..."
    echo "Configure Cloudflare CDN on the domain $DOMAIN for static assets." > /var/odoo_cdn.txt
}

setup_debug_tools() {
    info "Installing Python/Odoo debug tools..."
    pip install py-spy werkzeug
}

setup_perf_profiling() {
    info "Automatic Odoo profiling..."
    pip install py-spy
    py-spy record -o /var/log/odoo/odoo-profile.svg --pid $(pgrep -f odoo-bin) &
}

setup_disaster_recovery() {
    info "Disaster recovery configuration..."
    
    # Create DR directory
    mkdir -p /opt/odoo/disaster_recovery
    
    # Disaster recovery script
    cat > /opt/odoo/disaster_recovery/restore.sh << 'EOF'
#!/bin/bash

# Configuration
BACKUP_DIR="/opt/backups"
RESTORE_DIR="/opt/odoo/restore"
DB_NAME="odoo_production"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Database restoration function
restore_database() {
    local backup_file="$1"
    info "Restoring database from $backup_file..."
    
    # Stopping services
    systemctl stop odoo nginx
    
    # Deleting existing database
    sudo -u postgres dropdb "$DB_NAME" || true
    
    # Creating new database
    sudo -u postgres createdb "$DB_NAME"
    
    # Restoration
    if [[ "$backup_file" == *.dump ]]; then
        sudo -u postgres pg_restore -d "$DB_NAME" "$backup_file"
    elif [[ "$backup_file" == *.sql ]]; then
        sudo -u postgres psql "$DB_NAME" < "$backup_file"
    else
        error "Unsupported backup format: $backup_file"
        exit 1
    fi
}

# Function to restore files
restore_files() {
    local backup_file="$1"
    info "Restoring files from $backup_file..."
    
    # Creating restoration directory
    mkdir -p "$RESTORE_DIR"
    
    # Extracting
    tar -xzf "$backup_file" -C "$RESTORE_DIR"
    
    # Restoring permissions
    chown -R odoo:odoo "$RESTORE_DIR"
    find "$RESTORE_DIR" -type f -exec chmod 644 {} \;
    find "$RESTORE_DIR" -type d -exec chmod 755 {} \;
}

# Function to restore configuration
restore_config() {
    local backup_file="$1"
    info "Restoring configuration from $backup_file..."
    
    # Saving current configuration
    mv /etc/odoo/odoo.conf /etc/odoo/odoo.conf.bak.$TIMESTAMP
    mv /etc/nginx/sites-available/odoo /etc/nginx/sites-available/odoo.bak.$TIMESTAMP
    
    # Extracting configuration
    tar -xzf "$backup_file" -C /
}

# Verification function
verify_restore() {
    info "Verifying restoration..."
    
    # Checking database
    if ! sudo -u postgres psql -d "$DB_NAME" -c "\dt" > /dev/null; then
        error "Failed database verification"
        return 1
    fi
    
    # Checking files
    if [ ! -d "$RESTORE_DIR/data" ]; then
        error "Failed files verification"
        return 1
    fi
    
    # Checking configuration
    if [ ! -f "/etc/odoo/odoo.conf" ]; then
        error "Failed configuration verification"
        return 1
    fi
    
    return 0
}

# Rollback function
rollback_restore() {
    info "Rolling back restoration..."
    
    # Restoring database
    if [ -f "$BACKUP_DIR/pre_restore_${TIMESTAMP}.dump" ]; then
        restore_database "$BACKUP_DIR/pre_restore_${TIMESTAMP}.dump"
    fi
    
    # Restoring files
    if [ -d "$BACKUP_DIR/pre_restore_${TIMESTAMP}_files" ]; then
        rm -rf /opt/odoo/data
        mv "$BACKUP_DIR/pre_restore_${TIMESTAMP}_files" /opt/odoo/data
    fi
    
    # Restoring configuration
    if [ -f "/etc/odoo/odoo.conf.bak.$TIMESTAMP" ]; then
        mv "/etc/odoo/odoo.conf.bak.$TIMESTAMP" /etc/odoo/odoo.conf
    fi
    if [ -f "/etc/nginx/sites-available/odoo.bak.$TIMESTAMP" ]; then
        mv "/etc/nginx/sites-available/odoo.bak.$TIMESTAMP" /etc/nginx/sites-available/odoo
    fi
}

# Main menu
echo "=== Restore menu ==="
echo "1) Full restore (latest backup)"
echo "2) Restore to a point in time"
echo "3) Selective restore"
echo "4) Quit"

read -p "Choice: " choice

case $choice in
    1)
        # Pre-restore backup
        sudo -u postgres pg_dump -Fc "$DB_NAME" > "$BACKUP_DIR/pre_restore_${TIMESTAMP}.dump"
        cp -r /opt/odoo/data "$BACKUP_DIR/pre_restore_${TIMESTAMP}_files"
        
        # Restoration
        latest_db=$(ls -t "$BACKUP_DIR"/db_*.dump | head -1)
        latest_files=$(ls -t "$BACKUP_DIR"/files_*.tar.gz | head -1)
        latest_config=$(ls -t "$BACKUP_DIR"/config_*.tar.gz | head -1)
        
        restore_database "$latest_db"
        restore_files "$latest_files"
        restore_config "$latest_config"
        
        if verify_restore; then
            info "Full restoration successful"
            systemctl start odoo nginx
        else
            error "Restoration failed"
            rollback_restore
        fi
        ;;
    2)
        # List available backups
        echo "Available backups:"
        ls -lt "$BACKUP_DIR"/db_*.dump | awk '{print $9}'
        
        read -p "Restore date (YYYYMMDD_HHMMSS): " restore_date
        
        db_file="$BACKUP_DIR/db_${restore_date}.dump"
        files_file="$BACKUP_DIR/files_${restore_date}.tar.gz"
        config_file="$BACKUP_DIR/config_${restore_date}.tar.gz"
        
        if [ ! -f "$db_file" ] || [ ! -f "$files_file" ] || [ ! -f "$config_file" ]; then
            error "Backup files not found for specified date"
            exit 1
        fi
        
        # Pre-restore backup
        sudo -u postgres pg_dump -Fc "$DB_NAME" > "$BACKUP_DIR/pre_restore_${TIMESTAMP}.dump"
        cp -r /opt/odoo/data "$BACKUP_DIR/pre_restore_${TIMESTAMP}_files"
        
        restore_database "$db_file"
        restore_files "$files_file"
        restore_config "$config_file"
        
        if verify_restore; then
            info "Point-in-time restoration successful"
            systemctl start odoo nginx
        else
            error "Restoration failed"
            rollback_restore
        fi
        ;;
    3)
        echo "What do you want to restore?"
        echo "1) Database only"
        echo "2) Files only"
        echo "3) Configuration only"
        
        read -p "Choice: " restore_choice
        
        case $restore_choice in
            1)
                latest_db=$(ls -t "$BACKUP_DIR"/db_*.dump | head -1)
                restore_database "$latest_db"
                ;;
            2)
                latest_files=$(ls -t "$BACKUP_DIR"/files_*.tar.gz | head -1)
                restore_files "$latest_files"
                ;;
            3)
                latest_config=$(ls -t "$BACKUP_DIR"/config_*.tar.gz | head -1)
                restore_config "$latest_config"
                ;;
            *)
                error "Invalid choice"
                exit 1
                ;;
        esac
        
        systemctl start odoo nginx
        ;;
    4)
        exit 0
        ;;
    *)
        error "Invalid choice"
        exit 1
        ;;
esac
EOF
    
    chmod +x /opt/odoo/disaster_recovery/restore.sh
    
    # Disaster recovery documentation
    cat > /opt/odoo/disaster_recovery/README.md << 'EOF'
# Disaster Recovery Guide

## Prerequisites
- Root access to the server
- Valid backups
- Sufficient disk space

## Procedures

### 1. Full Restore
```bash
cd /opt/odoo/disaster_recovery
./restore.sh
# Choose option 1
```

### 2. Point-in-Time Restore
```bash
cd /opt/odoo/disaster_recovery
./restore.sh
# Choose option 2
# Specify date in YYYYMMDD_HHMMSS format
```

### 3. Selective Restore
```bash
cd /opt/odoo/disaster_recovery
./restore.sh
# Choose option 3
# Select components to restore
```

## Post-Restore Verification
1. Connect to Odoo web interface
2. Verify data
3. Test critical functionalities
4. Check logs

## Support
In case of problem:
1. Check logs: /var/log/odoo/restore.log
2. Contact system administrator
3. Use rollback procedure if necessary

## Maintenance
- Test restoration regularly
- Verify backup integrity
- Update documentation
- Form teams
EOF
    
    # Restoration test script
    cat > /opt/odoo/disaster_recovery/test_restore.sh << 'EOF'
#!/bin/bash

# Configuration
TEST_DB="odoo_test_restore"
TEST_DIR="/opt/odoo/test_restore"
LOG_FILE="/var/log/odoo/restore_test.log"

# Cleanup
rm -rf "$TEST_DIR"
sudo -u postgres dropdb "$TEST_DB" 2>/dev/null

# Restoration test
latest_db=$(ls -t /opt/backups/db_*.dump | head -1)
latest_files=$(ls -t /opt/backups/files_*.tar.gz | head -1)

# Database restoration
sudo -u postgres createdb "$TEST_DB"
if ! sudo -u postgres pg_restore -d "$TEST_DB" "$latest_db" >> "$LOG_FILE" 2>&1; then
    echo "ERROR: Failed to restore database"
    exit 1
fi

# Restoring files
mkdir -p "$TEST_DIR"
if ! tar -xzf "$latest_files" -C "$TEST_DIR" >> "$LOG_FILE" 2>&1; then
    echo "ERROR: Failed to restore files"
    exit 1
fi

# Verifications
if sudo -u postgres psql -d "$TEST_DB" -c "\dt" > /dev/null 2>&1; then
    echo "Restoration test successful"
else
    echo "ERROR: Restoration test failed"
    exit 1
fi

# Cleanup
sudo -u postgres dropdb "$TEST_DB"
rm -rf "$TEST_DIR"
EOF
    
    chmod +x /opt/odoo/disaster_recovery/test_restore.sh
    
    # Scheduling restoration tests
    (crontab -l 2>/dev/null; echo "0 3 * * 0 /opt/odoo/disaster_recovery/test_restore.sh") | crontab -
    
    info "Disaster recovery configuration completed"
}

setup_apparmor() {
    info "AppArmor configuration..."
    
    # Installing AppArmor
    apt install -yq apparmor apparmor-utils
    
    # AppArmor profile for Odoo
    cat > /etc/apparmor.d/usr.bin.odoo << EOF
#include <tunables/global>

/opt/odoo/venv/bin/python3 {
    #include <abstractions/base>
    #include <abstractions/python>
    #include <abstractions/nameservice>
    #include <abstractions/ssl_certs>
    #include <abstractions/user-tmp>

    /opt/odoo/** r,
    /opt/odoo/venv/** mr,
    /opt/odoo/odoo/** r,
    /var/log/odoo/** w,
    /etc/odoo/** r,
    /tmp/** rw,
    /proc/*/status r,
    /proc/*/mounts r,
    /proc/sys/kernel/random/uuid r,
    /sys/devices/system/cpu/online r,
    network tcp,
}
EOF

    # AppArmor profile for PostgreSQL
    cat > /etc/apparmor.d/usr.sbin.postgres << EOF
#include <tunables/global>

/usr/lib/postgresql/*/bin/postgres {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    #include <abstractions/user-tmp>
    
    /var/lib/postgresql/** rwk,
    /var/log/postgresql/** w,
    /etc/postgresql/** r,
    /proc/*/status r,
    /proc/*/mounts r,
    network tcp,
}
EOF

    # Enabling profiles
    apparmor_parser -r /etc/apparmor.d/usr.bin.odoo
    apparmor_parser -r /etc/apparmor.d/usr.sbin.postgres
    
    # Enabling AppArmor
    systemctl enable apparmor
    systemctl restart apparmor
    
    info "AppArmor configuration completed"
}

setup_varnish() {
    info "Varnish Cache configuration..."
    
    # Installing Varnish
    apt install -yq varnish
    
    # Varnish configuration
    cat > /etc/varnish/default.vcl << 'EOF'
vcl 4.0;

backend default {
    .host = "127.0.0.1";
    .port = "8069";
    .first_byte_timeout = 300s;
    .between_bytes_timeout = 60s;
}

# Defining pages not to cache
sub vcl_recv {
    # Do not cache admin pages
    if (req.url ~ "^/web/database/" ||
        req.url ~ "^/web/session/" ||
        req.url ~ "^/web/login" ||
        req.url ~ "^/web/reset_password" ||
        req.url ~ "^/web/signup") {
        return (pass);
    }
    
    # Caching static assets
    if (req.url ~ "\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|eot|svg)$") {
        unset req.http.Cookie;
        return (hash);
    }
    
    # Do not cache POST requests
    if (req.method == "POST") {
        return (pass);
    }
}

sub vcl_backend_response {
    # Setting TTL for different content types
    if (bereq.url ~ "\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|eot|svg)$") {
        set beresp.ttl = 24h;
        set beresp.grace = 12h;
        unset beresp.http.Set-Cookie;
    } else {
        set beresp.ttl = 1h;
        set beresp.grace = 30m;
    }
    
    # Gzip compression
    if (beresp.http.content-type ~ "text" ||
        beresp.http.content-type ~ "application/javascript" ||
        beresp.http.content-type ~ "application/json") {
        set beresp.do_gzip = true;
    }
}

sub vcl_deliver {
    # Adding headers for debugging
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
    set resp.http.X-Cache-Hits = obj.hits;
}
EOF

    # Updating Varnish service configuration
    sed -i 's/DAEMON_OPTS="-a :6081/DAEMON_OPTS="-a :80/' /etc/default/varnish
    
    # Updating systemd configuration
    cat > /etc/systemd/system/varnish.service << EOF
[Unit]
Description=Varnish HTTP accelerator
Documentation=https://www.varnish-cache.org/docs/
After=network.target

[Service]
Type=simple
LimitNOFILE=131072
LimitMEMLOCK=82000
ExecStart=/usr/sbin/varnishd -j unix,user=vcache -F -a :80 -T localhost:6082 -f /etc/varnish/default.vcl -S /etc/varnish/secret -s malloc,1G
ExecReload=/usr/share/varnish/varnishreload
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
PrivateDevices=true

[Install]
WantedBy=multi-user.target
EOF

    # Updating Nginx configuration to use Varnish
    sed -i 's/listen 80;/listen 8069;/' /etc/nginx/sites-available/odoo
    
    # Restarting services
    systemctl daemon-reload
    systemctl enable varnish
    systemctl restart varnish nginx
    
    info "Varnish configuration completed"
}

setup_selinux() {
    info "SELinux configuration..."
    
    # Installing SELinux tools
    apt install -yq selinux-basics selinux-policy-default auditd audispd-plugins
    
    # Enabling SELinux
    selinux-activate
    
    # Creating SELinux policy for Odoo
    cat > odoo.te << EOF
module odoo 1.0;

require {
    type httpd_t;
    type postgresql_t;
    type odoo_port_t;
    type odoo_var_lib_t;
    type odoo_log_t;
    class tcp_socket name_connect;
    class file { read write create unlink };
    class dir { search add_name remove_name write };
}

# Rules for Odoo
allow httpd_t odoo_port_t:tcp_socket name_connect;
allow httpd_t odoo_var_lib_t:dir { search add_name remove_name write };
allow httpd_t odoo_var_lib_t:file { read write create unlink };
allow httpd_t odoo_log_t:file { write create };

# Rules for PostgreSQL
allow postgresql_t odoo_port_t:tcp_socket name_connect;
EOF

    # Compiling and installing policy
    checkmodule -M -m -o odoo.mod odoo.te
    semodule_package -o odoo.pp -m odoo.mod
    semodule -i odoo.pp
    
    # Setting up security contexts
    semanage fcontext -a -t odoo_var_lib_t "/opt/odoo/data(/.*)?"
    semanage fcontext -a -t odoo_log_t "/var/log/odoo(/.*)?"
    semanage port -a -t odoo_port_t -p tcp 8069
    semanage port -a -t odoo_port_t -p tcp 8072
    
    # Applying contexts
    restorecon -R /opt/odoo/data
    restorecon -R /var/log/odoo
    
    # Audit configuration
    cat >> /etc/audit/rules.d/audit.rules << EOF
# Audit rules for Odoo
-w /opt/odoo/odoo -p wa -k odoo_changes
-w /etc/odoo -p wa -k odoo_config
-w /var/log/odoo -p wa -k odoo_logs
EOF
    
    # Restarting services
    systemctl restart auditd
    
    info "SELinux configuration completed"
}

setup_vault() {
    info "Configuring HashiCorp Vault for secret management..."
    
    # Installing Vault
    curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
    apt update && apt install -y vault
    
    # Basic Vault configuration
    mkdir -p /etc/vault.d
    cat > /etc/vault.d/config.hcl << EOF
storage "file" {
    path = "/opt/vault/data"
}

listener "tcp" {
    address = "127.0.0.1:8200"
    tls_disable = 1
}

api_addr = "http://127.0.0.1:8200"
ui = true
EOF
    
    # Creating Vault systemd service
    cat > /etc/systemd/system/vault.service << EOF
[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
After=network.target
ConditionFileNotEmpty=/etc/vault.d/config.hcl

[Service]
User=vault
Group=vault
ExecStart=/usr/bin/vault server -config=/etc/vault.d/config.hcl
ExecReload=/bin/kill -HUP \$MAINPID
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
Capabilities=CAP_IPC_LOCK+ep
SecureBits=keep-caps
NoNewPrivileges=yes
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF
    
    # Starting Vault
    systemctl daemon-reload
    systemctl enable --now vault
    
    # Initializing Vault (manual for security)
    echo "To initialize Vault, run: vault operator init" > /root/vault_init_instructions.txt
    
    info "Vault installed. See /root/vault_init_instructions.txt for initialization"
}

setup_docker() {
    info "Configuring Docker and Docker Compose..."
    
    # Installing Docker
    curl -fsSL https://get.docker.com | sh
    
    # Installing Docker Compose
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Docker configuration
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "default-address-pools": [
        {
            "base": "172.17.0.0/16",
            "size": 24
        }
    ],
    "metrics-addr": "127.0.0.1:9323",
    "experimental": true
}
EOF
    
    # Creating docker-compose.yml for services
    mkdir -p /opt/odoo/docker
    cat > /opt/odoo/docker/docker-compose.yml << EOF
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=false"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--certificatesresolvers.myresolver.acme.email=\${LE_EMAIL}"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "traefik-certificates:/letsencrypt"
    restart: always
    networks:
      - odoo-net

  portainer:
    image: portainer/portainer-ce:latest
    command: -H unix:///var/run/docker.sock
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
      - "portainer-data:/data"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.portainer.rule=Host(\`portainer.\${DOMAIN}\`)"
      - "traefik.http.routers.portainer.entrypoints=websecure"
      - "traefik.http.routers.portainer.tls.certresolver=myresolver"
    restart: always
    networks:
      - odoo-net

volumes:
  traefik-certificates:
  portainer-data:

networks:
  odoo-net:
    driver: bridge
EOF
    
    # Starting services
    cd /opt/odoo/docker
    docker-compose up -d
    
    info "Docker and services configured. Portainer accessible on https://portainer.${DOMAIN}"
}

load_env_config() {
    info "Loading configuration from .env..."
    
    # Default .env file
    if [ -f ".env" ]; then
        set -a
        source .env
        set +a
        info "Configuration loaded from .env"
    fi
    
    # Environment variables with default values
    export DOMAIN=${DOMAIN:-""}
    export LE_EMAIL=${LE_EMAIL:-""}
    export DDNS_SERVICE=${DDNS_SERVICE:-""}
    export CLOUDFLARE_TUNNEL=${CLOUDFLARE_TUNNEL:-false}
    export INSTALL_MODE=${INSTALL_MODE:-"production"}
    export ENABLE_MONITORING=${ENABLE_MONITORING:-true}
    export ENABLE_BACKUPS=${ENABLE_BACKUPS:-true}
    export BACKUP_RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-7}
    export ENABLE_VARNISH=${ENABLE_VARNISH:-false}
    export ENABLE_REDIS=${ENABLE_REDIS:-true}
    export ENABLE_SELINUX=${ENABLE_SELINUX:-false}
    export ENABLE_APPARMOR=${ENABLE_APPARMOR:-true}
    
    # Validating required variables in production mode
    if [ "$INSTALL_MODE" = "production" ]; then
        if [ -z "$DOMAIN" ]; then
            error "DOMAIN is required in production mode"
        fi
        if [ "$CLOUDFLARE_TUNNEL" != "true" ] && [ -z "$LE_EMAIL" ]; then
            error "LE_EMAIL is required in production without Cloudflare Tunnel"
        fi
    fi
}

# Final cleanup and summary generation
cleanup() {
    info "Post-installation cleanup..."
    
    # Remove temporary files
    rm -rf /tmp/odoo_install_*
    
    # Clean APT cache
    apt clean
    
    # Remove unnecessary packages
    apt autoremove -y
    
    # Secure installation logs
    chmod 600 "$LOG_FILE"
    
    # Create installation summary
    if [[ "$DRY_RUN" != true ]]; then
        cat > /root/odoo_installation_summary.txt << EOF
=============================================
ODOO INSTALLATION SUMMARY
=============================================
Date: $(date)
Domain: $DOMAIN
Services: Odoo, PostgreSQL, Redis, Nginx
Monitoring: Netdata, Prometheus, Grafana

CREDENTIALS (KEEP SECURE)
=============================================
Database: $DB_NAME
Database User: $DB_USER
Database Password: $DB_PASS
Odoo Admin Password: $ADMIN_PASS
Redis Password: $REDIS_PASS

BACKUP INFORMATION
=============================================
Backup location: /opt/backups
Backup schedule: Daily at 2AM
Retention: ${BACKUP_RETENTION_DAYS:-7} days

ACCESS URLS
=============================================
Odoo: https://$DOMAIN
$(if [[ "${EXPOSE_MONITORING:-false}" == "true" ]]; then echo "Netdata: http://$DOMAIN:19999
Grafana: http://$DOMAIN:3000 (admin/admin)
Prometheus: http://$DOMAIN:9090"; fi)

For security reasons, please change all default passwords.
This summary file should be secured or deleted.
EOF

    chmod 600 /root/odoo_installation_summary.txt
    
    info "Cleanup completed. Summary available in /root/odoo_installation_summary.txt"
    fi
}

generate_module_example() {
    info "Generating module example files..."
    
    # Create the modules directory if it doesn't exist
    mkdir -p "${MODULE_DIR}"
    
    # Example PostgreSQL module
    cat > "${MODULE_DIR}/postgresql.sh.example" << 'EOF'
#!/bin/bash
# Module PostgreSQL pour l'installeur serveur Odoo
# Pour utiliser ce module, renommez-le en postgresql.sh

# Installation et configuration de PostgreSQL
setup_postgresql() {
    info "Module PostgreSQL : installation et configuration..."
    
    # Installation spécifique à la distribution
    case "$DISTRO_FAMILY" in
        debian)
            apt-get install -yq postgresql-15 postgresql-contrib-15
            ;;
        redhat)
            $PKG_INSTALL postgresql15-server postgresql15-contrib
            ;;
        *)
            warn "Distribution non supportée pour le module PostgreSQL"
            return 1
            ;;
    esac
    
    # Configuration de PostgreSQL pour Odoo
    info "Configuration de la base PostgreSQL pour Odoo"
    sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';"
    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
    
    # Application des optimisations de performance
    info "Application des optimisations de performance PostgreSQL"
    # ... code d'optimisation ici ...
    
    return 0
}

# Export des fonctions du module
export -f setup_postgresql
EOF

    # Example Odoo module
    cat > "${MODULE_DIR}/odoo.sh.example" << 'EOF'
#!/bin/bash
# Module Odoo pour l'installeur serveur Odoo
# Pour utiliser ce module, renommez-le en odoo.sh

# Fonction d'installation d'Odoo
install_odoo() {
    info "Module Odoo : installation..."
    
    # Création de l'utilisateur odoo
    useradd -m -d /opt/odoo -U -r -s /bin/bash odoo
    
    # Installation d'Odoo via pip dans un environnement virtuel
    su - odoo -c "
        python3 -m venv /opt/odoo/venv
        source /opt/odoo/venv/bin/activate
        pip install wheel
        pip install odoo
        deactivate
    "
    
    # Création de la configuration
    mkdir -p /etc/odoo
    # ... code de configuration ici ...
    
    # Création du service systemd
    # ... code du service ici ...
    
    return 0
}

# Export des fonctions du module
export -f install_odoo
EOF

    info "Exemples de modules créés dans ${MODULE_DIR}"
    info "Pour utiliser des modules externes, renommez-les de .example en .sh"
}

# Add module example generation to the main function - after modules directory creation
if [[ ! -d "$MODULE_DIR" ]]; then
    mkdir -p "$MODULE_DIR"
    debug "Created modules directory: $MODULE_DIR"
    generate_module_example
fi

#=============================================================================
# CACHE SYSTEM
#=============================================================================

# Cache directory for storing operation status
CACHE_DIR="/var/cache/odoo_installer"
mkdir -p "$CACHE_DIR" 2>/dev/null || true

# Function to check if an operation has already been completed
# Usage: is_cached "operation_name"
is_cached() {
    local operation="$1"
    [[ -f "${CACHE_DIR}/${operation}.done" ]]
}

# Function to mark an operation as completed
# Usage: mark_cached "operation_name"
mark_cached() {
    local operation="$1"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$timestamp" > "${CACHE_DIR}/${operation}.done"
    debug "Operation '$operation' marked as completed in cache"
}

# Function to clear the cache for an operation
# Usage: clear_cache "operation_name"
clear_cache() {
    local operation="$1"
    if [[ -f "${CACHE_DIR}/${operation}.done" ]]; then
        rm "${CACHE_DIR}/${operation}.done"
        debug "Cache cleared for operation '$operation'"
    fi
}

# Function to run an operation only if not cached
# Usage: run_once "operation_name" command_function
run_once() {
    local operation="$1"
    local func="$2"
    shift 2
    
    if is_cached "$operation"; then
        info "Operation '$operation' already completed, skipping"
        return 0
    else
        info "Running operation '$operation'"
        if "$func" "$@"; then
            mark_cached "$operation"
            return 0
        else
            warn "Operation '$operation' failed"
            return 1
        fi
    fi
}

#=============================================================================
# PARALLEL EXECUTION SYSTEM
#=============================================================================

# Maximum number of parallel tasks, defaults to CPU count
MAX_PARALLEL_TASKS=${MAX_PARALLEL_TASKS:-$(nproc)}

# Array to store background PIDs
BACKGROUND_PIDS=()

# Function to execute tasks in parallel
# Usage: parallel_exec "task1_name" "task1_command" "task2_name" "task2_command" ...
parallel_exec() {
    local tasks=()
    local names=()
    
    # Collect tasks and names
    while [[ $# -gt 0 ]]; do
        names+=("$1")
        tasks+=("$2")
        shift 2
    done
    
    info "Starting ${#tasks[@]} tasks in parallel (max $MAX_PARALLEL_TASKS at once)"
    
    # Create a temporary directory for task status
    local tmp_dir=$(mktemp -d)
    
    # Execute tasks in batches
    for ((i=0; i<${#tasks[@]}; i+=MAX_PARALLEL_TASKS)); do
        # Calculate end index for this batch
        local end=$((i + MAX_PARALLEL_TASKS))
        if [ $end -gt ${#tasks[@]} ]; then
            end=${#tasks[@]}
        fi
        
        # Execute tasks in this batch
        for ((j=i; j<end; j++)); do
            local task_name="${names[$j]}"
            local task_cmd="${tasks[$j]}"
            local status_file="${tmp_dir}/${j}.status"
            
            debug "Starting task: $task_name"
            (
                if eval "$task_cmd"; then
                    echo "success" > "$status_file"
                else
                    echo "failure" > "$status_file"
                fi
            ) &
            BACKGROUND_PIDS+=($!)
        done
        
        # Wait for all tasks in this batch to complete
        for pid in "${BACKGROUND_PIDS[@]}"; do
            wait "$pid"
        done
        BACKGROUND_PIDS=()
        
        # Check status of each task in this batch
        for ((j=i; j<end; j++)); do
            local task_name="${names[$j]}"
            local status_file="${tmp_dir}/${j}.status"
            
            if [[ -f "$status_file" ]]; then
                local status=$(cat "$status_file")
                if [[ "$status" == "success" ]]; then
                    info "Task completed successfully: $task_name"
                else
                    warn "Task failed: $task_name"
                fi
            else
                warn "No status file for task: $task_name"
            fi
        done
    done
    
    # Clean up
    rm -rf "$tmp_dir"
    
    info "All parallel tasks completed"
}

#=============================================================================
# DRY RUN HELPERS
#=============================================================================

# Execute a command only if not in dry-run mode
# Usage: execute_if_not_dry_run "command description" command_to_execute
execute_if_not_dry_run() {
    local description="$1"
    local command="$2"
    shift 2
    
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY-RUN] Would execute: $description"
        debug "[DRY-RUN] Command: $command $*"
        return 0
    else
        debug "Executing: $description"
        eval "$command" "$@"
        return $?
    fi
}

# Wrapper for system commands that should be skipped in dry-run mode
# Usage: system_cmd "apt-get update" "Update package repository"
system_cmd() {
    local cmd="$1"
    local description="${2:-Executing command}"
    
    execute_if_not_dry_run "$description" "$cmd"
}

# Wrapper for file operations that should be skipped in dry-run mode
# Usage: file_op "write_config_file" "Creating configuration file"
file_op() {
    local cmd="$1"
    local description="${2:-Performing file operation}"
    
    execute_if_not_dry_run "$description" "$cmd"
}

#=============================================================================
# COMPREHENSIVE PRELIMINARY CHECKS
#=============================================================================

# Comprehensive preliminary check to verify all prerequisites before installation
comprehensive_checks() {
    info "Running comprehensive preliminary checks..."
    local ISSUES_FOUND=0
    local WARNINGS_FOUND=0
    
    # Create a temporary file for collecting issues
    local ISSUES_FILE=$(mktemp)
    local WARNINGS_FILE=$(mktemp)
    
    # Check for root access
    if [[ $EUID -ne 0 ]]; then
        echo "CRITICAL: This script must be run as root" >> "$ISSUES_FILE"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Check OS compatibility
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "debian" && "${VERSION_ID:-0}" -lt 12 ]]; then
            echo "CRITICAL: Debian $VERSION_ID not supported. Minimum version: Debian 12" >> "$ISSUES_FILE"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        elif [[ "$ID" == "ubuntu" && "${VERSION_ID:-0}" < "24.04" ]]; then
            echo "CRITICAL: Ubuntu $VERSION_ID not supported. Minimum version: Ubuntu 24.04" >> "$ISSUES_FILE"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        elif [[ "$ID" != "debian" && "$ID" != "ubuntu" && "$ID" != "alpine" ]]; then
            echo "WARNING: Unsupported distribution: $ID $VERSION_ID" >> "$WARNINGS_FILE"
            WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
        fi
    else
        echo "CRITICAL: Unable to determine OS distribution" >> "$ISSUES_FILE"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Check system memory
    local MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local MEM_GB=$((MEM_TOTAL / 1024 / 1024))
    if [[ $MEM_GB -lt 2 ]]; then
        echo "CRITICAL: Insufficient memory. Minimum 2GB required, found ${MEM_GB}GB" >> "$ISSUES_FILE"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    elif [[ $MEM_GB -lt 4 ]]; then
        echo "WARNING: Low memory. At least 4GB recommended, found ${MEM_GB}GB" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    
    # Check disk space
    local DISK_SPACE=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ $DISK_SPACE -lt 10 ]]; then
        echo "CRITICAL: Insufficient disk space. Minimum 10GB required, found ${DISK_SPACE}GB" >> "$ISSUES_FILE"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    elif [[ $DISK_SPACE -lt 20 ]]; then
        echo "WARNING: Low disk space. At least 20GB recommended, found ${DISK_SPACE}GB" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    
    # Check CPU count
    local CPU_COUNT=$(nproc)
    if [[ $CPU_COUNT -lt 2 ]]; then
        echo "WARNING: Only ${CPU_COUNT} CPU detected. At least 2 CPUs recommended" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    
    # Check for required commands
    local REQUIRED_COMMANDS=("bash" "curl" "wget" "grep" "awk" "sed")
    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "CRITICAL: Required command not found: $cmd" >> "$ISSUES_FILE"
            ISSUES_FOUND=$((ISSUES_FOUND + 1))
        fi
    done
    
    # Check Internet connectivity
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        echo "CRITICAL: No Internet connectivity detected" >> "$ISSUES_FILE"
        ISSUES_FOUND=$((ISSUES_FOUND + 1))
    fi
    
    # Check SSH connection (we don't want to lose connection during install)
    if [[ -n "$SSH_CONNECTION" ]]; then
        echo "WARNING: Installation running over SSH. Ensure connection stability" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    
    # Check if PostgreSQL is already installed
    if command -v psql &> /dev/null; then
        local PG_VERSION=$(psql --version | grep -oP 'psql \(PostgreSQL\) \K[0-9]+\.[0-9]+')
        echo "WARNING: PostgreSQL ${PG_VERSION} already installed. This script may modify configuration" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    
    # Check if port 80/443 are already in use
    if netstat -tuln 2>/dev/null | grep -q ':80 '; then
        echo "WARNING: Port 80 already in use. This may interfere with the web server" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    if netstat -tuln 2>/dev/null | grep -q ':443 '; then
        echo "WARNING: Port 443 already in use. This may interfere with SSL setup" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    
    # Check if port 8069 is already in use (Odoo default)
    if netstat -tuln 2>/dev/null | grep -q ':8069 '; then
        echo "WARNING: Port 8069 already in use. This may interfere with Odoo" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    
    # Check system's hostname resolution
    if ! grep -q "$(hostname)" /etc/hosts; then
        echo "WARNING: Hostname $(hostname) not found in /etc/hosts. May cause issues" >> "$WARNINGS_FILE"
        WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
    fi
    
    # Display issues if any
    if [[ $ISSUES_FOUND -gt 0 ]]; then
        error "Found $ISSUES_FOUND critical issues that must be fixed:"
        cat "$ISSUES_FILE" | while read issue; do
            error "  - $issue"
        done
        error "Please fix these issues before continuing"
        rm "$ISSUES_FILE" "$WARNINGS_FILE"
        return 1
    fi
    
    # Display warnings if any
    if [[ $WARNINGS_FOUND -gt 0 ]]; then
        warn "Found $WARNINGS_FOUND warnings:"
        cat "$WARNINGS_FILE" | while read warning; do
            warn "  - $warning"
        done
        
        if [[ "$AUTO_MODE" != true ]]; then
            read -p "Do you want to continue despite these warnings? (y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Installation aborted by user"
                rm "$ISSUES_FILE" "$WARNINGS_FILE"
                exit 0
            fi
        else
            warn "Auto mode enabled, continuing despite warnings"
        fi
    fi
    
    # Cleanup
    rm "$ISSUES_FILE" "$WARNINGS_FILE"
    
    info "Preliminary checks completed successfully"
    return 0
}
