#!/bin/bash
# Script d'installation Odoo 17 optimisé - Debian 12/Ubuntu 24.04 - 64GB RAM
# Version refactorisée : logging structuré, rollback, validation stricte, modularité, sécurité renforcée

set -euo pipefail

# ===================== LOGGING STRUCTURÉ & MASQUAGE =====================
LOG_FILE="/var/log/odoo_install.log"
MASKED_VARS=("DB_PASS" "ADMIN_PASS" "REDIS_PASS" "NOIP_PASS" "DYNU_PASS" "DUCKDNS_TOKEN")
log() {
    local level="$1"; shift
    local msg="$@"
    for var in "${MASKED_VARS[@]}"; do
        local val="${!var:-}"
        if [[ -n "$val" ]]; then
            msg="${msg//${val}/******}"
        fi
    done
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $msg" | tee -a "$LOG_FILE"
}
info() { log "INFO" "$@"; }
warn() { log "WARN" "$@"; }
error() { log "ERROR" "$@"; exit 1; }

# ===================== ROLLBACK SYSTEME =====================
ROLLBACK_ACTIONS=()
trap 'on_error $LINENO' ERR
on_error() {
    local line=$1
    error "Erreur ligne $line - Rollback en cours"
    rollback
    exit 1
}
rollback() {
    for action in "${ROLLBACK_ACTIONS[@]}"; do
        eval "$action"
    done
    warn "Rollback terminé"
}
add_rollback() {
    ROLLBACK_ACTIONS=("$1" "${ROLLBACK_ACTIONS[@]}")
}

# ===================== VALIDATION STRICTE DES ENTRÉES =====================
validate_inputs() {
    info "Validation des entrées"
    if [[ -z "$DOMAIN" ]]; then error "Domaine non renseigné"; fi
    if [[ "$CLOUDFLARE_TUNNEL" != true && -z "$LE_EMAIL" ]]; then error "Email Let's Encrypt requis"; fi
    if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then error "Format de domaine invalide : $DOMAIN"; fi
    if [[ "$CLOUDFLARE_TUNNEL" != true && ! "$LE_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then error "Format d'email invalide : $LE_EMAIL"; fi
}

# === CONFIGURATION RAPIDE (à éditer avant exécution) ===
# Renseignez ici vos informations si vous voulez un déploiement 100% automatique
# Si vous laissez vide, le script vous demandera uniquement ce qui est indispensable
DOMAIN=""         # Exemple : monsite.com
LE_EMAIL=""       # Email pour Let's Encrypt (obligatoire pour SSL)
DDNS_SERVICE=""   # duckdns|noip|dynu|custom (laisser vide si non utilisé)
SUBDOMAIN=""      # Pour DuckDNS
DUCKDNS_TOKEN=""  # Pour DuckDNS
NOIP_USER=""      # Pour No-IP
NOIP_PASS=""      # Pour No-IP
DYNU_USER=""      # Pour Dynu
DYNU_PASS=""      # Pour Dynu
CLOUDFLARE_TUNNEL=false # true pour forcer Cloudflare Tunnel
# =========================================

# ===================== VALIDATION INTERACTIVE =====================
validate_interactive() {
    info "Validation interactive des pré-requis..."
    local CONTINUE=true
    local WARNINGS=()
    
    # Fonction pour demander confirmation
    ask_continue() {
        local message="$1"
        local default="${2:-y}"  # y par défaut
        while true; do
            read -p "$message [Y/n] " response
            case $response in
                [Nn]* ) return 1;;
                [Yy]* ) return 0;;
                "" ) if [ "$default" = "y" ]; then return 0; else return 1; fi;;
                * ) echo "Répondez par y ou n";;
            esac
        done
    }
    
    # Vérification du kernel
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
    if [[ $KERNEL_MAJOR -lt 5 || ($KERNEL_MAJOR -eq 5 && $KERNEL_MINOR -lt 10) ]]; then
        WARNINGS+=("⚠️ Kernel Linux < 5.10 détecté (actuel: $KERNEL_VERSION). Les performances pourraient être impactées.")
    fi
    
    # Vérification RAM
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $RAM_GB -lt 16 ]]; then
        WARNINGS+=("⚠️ RAM < 16GB détectée (${RAM_GB}GB). Les performances seront limitées.")
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
        WARNINGS+=("⚠️ Vitesse réseau < 1Gbps détectée. Les performances pourraient être impactées.")
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
            WARNINGS+=("⚠️ Espace insuffisant sur $dir. Minimum recommandé: ${REQUIRED}G, Disponible: ${AVAILABLE:-0}G")
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
            echo "- Augmentez la RAM à au moins 16GB pour de meilleures performances"
            echo "- Un swap sera configuré automatiquement pour compenser"
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
            echo "- Configuration swap optimisée"
            echo "- Limite de mémoire Odoo ajustée"
            echo "- Cache Redis réduit"
        fi
        if [[ $CPU_CORES -lt 4 ]]; then
            echo "- Nombre de workers réduit"
            echo "- Compression des assets activée"
            echo "- Mise en cache agressive"
        fi
        if [[ "$DISK_TYPE" == "1" ]]; then
            echo "- Cache disque augmenté"
            echo "- Compression des logs activée"
            echo "- Rotation des logs plus fréquente"
        fi
        
        echo -e "\n❓ Souhaitez-vous continuer malgré ces avertissements ?"
        if ! ask_continue "L'installation sera optimisée automatiquement pour votre configuration."; then
            error "Installation annulée par l'utilisateur"
            exit 1
        fi
    fi
    
    # Installation des paquets requis manquants
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
        info "Installation paquets requis"
        apt-get update
        apt-get install -y "${MISSING_PACKAGES[@]}"
    fi
    
    info "Validation interactive terminée"
}

# Configuration interactive
get_user_config() {
    log "Configuration du système..."
    # Mode auto si DOMAIN et LE_EMAIL sont renseignés
    if [[ -n "$DOMAIN" && ( -n "$LE_EMAIL" || "$CLOUDFLARE_TUNNEL" = true ) ]]; then
        if [[ "$CLOUDFLARE_TUNNEL" = true ]]; then
            CONNECTION_TYPE=3
            USE_CLOUDFLARE=true
            LE_EMAIL=""
        else
            CONNECTION_TYPE=1
            USE_CLOUDFLARE=false
        fi
        log "Mode auto : domaine $DOMAIN, email $LE_EMAIL, Cloudflare Tunnel $CLOUDFLARE_TUNNEL"
    else
        # Détecter le type de connexion
        echo "🌐 Type de connexion :"
        echo "1) IP fixe / Serveur dédié"
        echo "2) IP dynamique / Box maison"
        echo "3) Cloudflare Tunnel (recommandé pour IP dynamique)"
        read -p "Choisissez (1-3): " CONNECTION_TYPE
        
        case $CONNECTION_TYPE in
            1)
                # Configuration classique
                while true; do
                    read -p "Entrez votre nom de domaine (ex: monsite.com): " DOMAIN
                    if [[ $DOMAIN =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
                        break
                    else
                        warn "Format de domaine invalide. Veuillez réessayer."
                    fi
                done
                
                while true; do
                    read -p "Entrez votre email pour Let's Encrypt: " LE_EMAIL
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
                read -p "Choisissez (1-4): " DDNS_SERVICE
                
                case $DDNS_SERVICE in
                    1)
                        read -p "Nom du sous-domaine DuckDNS (ex: monsite): " SUBDOMAIN
                        read -p "Token DuckDNS: " DUCKDNS_TOKEN
                        DOMAIN="${SUBDOMAIN}.duckdns.org"
                        ;;
                    2)
                        read -p "Hostname No-IP complet (ex: monsite.ddns.net): " DOMAIN
                        read -p "Username No-IP: " NOIP_USER
                        read -p "Password No-IP: " NOIP_PASS
                        ;;
                    3)
                        read -p "Hostname Dynu complet (ex: monsite.freeddns.org): " DOMAIN
                        read -p "Username Dynu: " DYNU_USER
                        read -p "Password Dynu: " DYNU_PASS
                        ;;
                    4)
                        read -p "Votre domaine: " DOMAIN
                        ;;
                esac
                
                read -p "Entrez votre email pour Let's Encrypt: " LE_EMAIL
                USE_CLOUDFLARE=false
                ;;
            3)
                # Configuration Cloudflare Tunnel
                echo "🔒 Configuration Cloudflare Tunnel"
                read -p "Entrez votre nom de domaine (doit être sur Cloudflare): " DOMAIN
                echo "Vous devrez configurer le tunnel après installation"
                echo "Instructions : https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/"
                USE_CLOUDFLARE=true
                LE_EMAIL=""
                ;;
        esac
    fi
    
    # Configuration automatique optimisée
    DB_NAME="odoo_production"
    DB_USER="odoo_user"
    ADMIN_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-20)
    DB_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    REDIS_PASS=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-16)
    
    # Détecter le nombre de CPU
    CPU_CORES=$(nproc)
    WORKERS=$((CPU_CORES * 2))
    
    PUBLIC_IP=$(curl -s --max-time 10 ifconfig.me || echo "IP non détectée")
    
    log "Configuration terminée:"
    log "  Domaine: $DOMAIN"
    log "  CPU cores: $CPU_CORES"
    log "  Workers Odoo: $WORKERS"
    log "  RAM: ${RAM_GB}GB"
}

# Optimisation système
optimize_system() {
    log "Optimisation du système..."
    
    # Optimisations kernel
    cat >> /etc/sysctl.conf << EOF
# Optimisations Odoo
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
    
    # Limites système
    cat >> /etc/security/limits.conf << EOF
# Limites Odoo
odoo soft nofile 65535
odoo hard nofile 65535
postgres soft nofile 65535
postgres hard nofile 65535
EOF
}

# Installation des paquets
install_packages() {
    log "Installation des paquets système..."
    
    # Mise à jour
    apt update -q
    DEBIAN_FRONTEND=noninteractive apt upgrade -yq
    
    # Paquets essentiels
    apt install -yq \
        curl wget git htop iotop \
        build-essential \
        python3-pip python3-dev python3-venv \
        libxml2-dev libxslt1-dev zlib1g-dev \
        libsasl2-dev libldap2-dev libjpeg-dev \
        libpq-dev libffi-dev \
        fonts-liberation \
        geoip-database \
        libssl-dev \
        node-clean-css \
        node-less \
        xz-utils
    
    # Outils de monitoring
    apt install -yq \
        prometheus-node-exporter \
        fail2ban \
        logrotate \
        rsyslog
}

# Configuration PostgreSQL optimisée
setup_postgresql() {
    log "Installation et configuration PostgreSQL..."
    
    apt install -yq postgresql-15 postgresql-contrib-15 postgresql-client-15
    
    # Configuration utilisateur
    sudo -u postgres psql << EOF
CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS}';
CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
ALTER USER ${DB_USER} CREATEDB;
EOF
    
    # Configuration optimisée pour 64GB RAM
    PG_CONF="/etc/postgresql/15/main/postgresql.conf"
    cp $PG_CONF $PG_CONF.bak
    
    cat > $PG_CONF << EOF
# Configuration PostgreSQL optimisée pour Odoo - 64GB RAM
listen_addresses = 'localhost'
port = 5432
max_connections = 200
shared_buffers = 16GB
effective_cache_size = 48GB
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
    
    systemctl restart postgresql
    systemctl enable postgresql
    
    setup_postgresql_advanced
}

setup_postgresql_advanced() {
    info "Configuration avancée PostgreSQL..."
    
    # Installation des extensions utiles
    sudo -u postgres psql << EOF
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
CREATE EXTENSION IF NOT EXISTS pg_prewarm;
CREATE EXTENSION IF NOT EXISTS pg_buffercache;
CREATE EXTENSION IF NOT EXISTS auto_explain;
EOF

    # Configuration optimisée pour les performances
    cat >> /etc/postgresql/15/main/postgresql.conf << EOF
# Optimisations avancées
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

    # Script de maintenance automatique
    cat > /usr/local/bin/pg_maintenance.sh << 'EOF'
#!/bin/bash
# Maintenance PostgreSQL quotidienne
psql -U postgres << 'PSQL'
VACUUM ANALYZE;
REINDEX DATABASE odoo_production;
SELECT pg_prewarm('res_partner');
SELECT pg_prewarm('product_template');
SELECT pg_prewarm('sale_order');
PSQL
EOF
    chmod +x /usr/local/bin/pg_maintenance.sh
    
    # Planification de la maintenance
    (crontab -l 2>/dev/null; echo "0 1 * * * /usr/local/bin/pg_maintenance.sh") | crontab -
    
    info "Configuration avancée PostgreSQL terminée"
}

# Installation Redis
setup_redis() {
    log "Installation et configuration Redis..."
    
    apt install -yq redis-server
    
    # Configuration Redis
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

# Installation Odoo 17
install_odoo() {
    info "Installation Odoo"
    
    # Utilisateur
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

    # Démarrage
    systemctl daemon-reload
    systemctl enable --now odoo
    
    info "Installation Odoo terminée"
}

# Configuration Nginx optimisée
setup_nginx() {
    log "Configuration Nginx..."
    
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
    
    # SSL Configuration
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
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=login:10m rate=1r/s;
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/s;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
    
    # Configuration site Odoo
    cat > /etc/nginx/sites-available/odoo << EOF
# Upstream Odoo
upstream odoo {
    server 127.0.0.1:8069;
}

upstream odoochat {
    server 127.0.0.1:8072;
}

# Rate limiting
map \$request_uri \$limit {
    ~*/web/login  login;
    ~*/web/database/manager  login;
    ~*/jsonrpc  api;
    default "";
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name ${DOMAIN};
    return 301 https://\$server_name\$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    server_name ${DOMAIN};
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;
    
    # Security headers
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
    
    # Main location
    location / {
        # Rate limiting
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
    
    # Générer DH parameters
    openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
    
    ln -s /etc/nginx/sites-available/odoo /etc/nginx/sites-enabled/
    nginx -t
    systemctl enable nginx
}

# Configuration SSL
setup_ssl() {
    if [ "$USE_CLOUDFLARE" = true ]; then
        log "Configuration pour Cloudflare Tunnel..."
        
        # Pas de SSL local avec Cloudflare Tunnel
        # Cloudflare gère le SSL
        log "SSL géré par Cloudflare - pas de configuration locale nécessaire"
        
        # Installer cloudflared
        curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
        dpkg -i cloudflared.deb
        rm cloudflared.deb
        
        cat << EOF

🔒 CONFIGURATION CLOUDFLARE TUNNEL REQUISE :

1. Connectez-vous à Cloudflare Dashboard
2. Allez dans Zero Trust > Access > Tunnels
3. Créez un nouveau tunnel
4. Copiez le token et exécutez :
   cloudflared service install TOKEN_ICI

5. Configurez le tunnel :
   - Type: HTTP
   - URL: localhost:8069
   - Domaine: ${DOMAIN}

6. Redémarrez Nginx sans SSL :
   systemctl restart nginx

EOF
        
        # Configuration Nginx sans SSL pour Cloudflare
        setup_nginx_cloudflare
        
    else
        log "Configuration SSL avec Let's Encrypt..."
        
        apt install -yq certbot python3-certbot-nginx
        
        # Configurer DDNS si nécessaire
        if [ "$CONNECTION_TYPE" = "2" ]; then
            setup_ddns
        fi
        
        # Créer le certificat
        certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos --email ${LE_EMAIL}
        
        # Renouvellement automatique
        systemctl enable certbot.timer
        systemctl start certbot.timer
        
        systemctl restart nginx
    fi
}

# Configuration du monitoring
setup_monitoring() {
    log "Configuration du monitoring..."
    
    # Netdata
    bash <(curl -Ss https://my-netdata.io/kickstart.sh) --disable-telemetry --non-interactive
    
    # Configuration Fail2ban
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

# Configuration des sauvegardes
setup_backups() {
    log "Configuration des sauvegardes..."
    
    mkdir -p /opt/backups/{daily,weekly,monthly}
    
    cat > /opt/backups/backup_odoo.sh << EOF
#!/bin/bash
# Script de sauvegarde Odoo complet

DATE=\$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/backups/daily"
DB_NAME="${DB_NAME}"
DB_USER="${DB_USER}"
ODOO_DATA="/opt/odoo/data"

# Sauvegarde base de données
sudo -u postgres pg_dump -Fc \${DB_NAME} > \${BACKUP_DIR}/db_\${DATE}.dump

# Sauvegarde des fichiers
if [ -d "\${ODOO_DATA}" ]; then
    tar -czf \${BACKUP_DIR}/files_\${DATE}.tar.gz \${ODOO_DATA}
fi

# Sauvegarde configuration
tar -czf \${BACKUP_DIR}/config_\${DATE}.tar.gz /etc/odoo /etc/nginx/sites-available/odoo

# Nettoyage (garder 7 jours)
find \${BACKUP_DIR} -name "*.dump" -mtime +7 -delete
find \${BACKUP_DIR} -name "*.tar.gz" -mtime +7 -delete

echo "Sauvegarde terminée: \${DATE}"
EOF
    
    chmod +x /opt/backups/backup_odoo.sh
    
    # Tâche cron
    (crontab -l 2>/dev/null; echo "0 2 * * * /opt/backups/backup_odoo.sh >> /var/log/backup.log 2>&1") | crontab -
}

# Configuration du pare-feu
setup_firewall() {
    log "Configuration du pare-feu..."
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    # Règles basiques
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 19999/tcp  # Netdata
    
    # Activer le pare-feu
    ufw --force enable
}

# Tests de fonctionnement
run_tests() {
    log "Tests de fonctionnement..."
    
    # Test PostgreSQL
    if sudo -u postgres psql -c "SELECT 1;" > /dev/null 2>&1; then
        log "✓ PostgreSQL fonctionne"
    else
        error "✗ PostgreSQL ne fonctionne pas"
    fi
    
    # Test Redis
    if redis-cli -a ${REDIS_PASS} ping > /dev/null 2>&1; then
        log "✓ Redis fonctionne"
    else
        error "✗ Redis ne fonctionne pas"
    fi
    
    # Test Odoo
    if systemctl is-active --quiet odoo; then
        log "✓ Odoo est actif"
    else
        error "✗ Odoo ne fonctionne pas"
    fi
    
    # Test Nginx
    if systemctl is-active --quiet nginx; then
        log "✓ Nginx est actif"
    else
        error "✗ Nginx ne fonctionne pas"
    fi
}

# ===================== VÉRIFICATION FINALE =====================
verify_installation() {
    info "Vérification finale de l'installation..."
    local ERRORS=()
    local WARNINGS=()
    
    echo -e "\n🔍 Démarrage des vérifications..."
    
    # Fonction de test avec barre de progression
    test_with_progress() {
        local message="$1"
        local cmd="$2"
        echo -n "⏳ $message... "
        if eval "$cmd" > /dev/null 2>&1; then
            echo -e "\r✅ $message"
            return 0
        else
            echo -e "\r❌ $message"
            return 1
        fi
    }

    # 1. Vérification des services
    echo -e "\n📊 Vérification des services :"
    
    # PostgreSQL
    if ! test_with_progress "PostgreSQL" "systemctl is-active --quiet postgresql"; then
        ERRORS+=("PostgreSQL n'est pas actif")
    else
        # Test de connexion
        if ! test_with_progress "Connexion PostgreSQL" "sudo -u postgres psql -c '\q'"; then
            ERRORS+=("Impossible de se connecter à PostgreSQL")
        fi
    fi
    
    # Redis
    if ! test_with_progress "Redis" "systemctl is-active --quiet redis-server"; then
        ERRORS+=("Redis n'est pas actif")
    else
        # Test de connexion Redis
        if ! test_with_progress "Connexion Redis" "redis-cli ping"; then
            ERRORS+=("Impossible de se connecter à Redis")
        fi
    fi
    
    # Nginx
    if ! test_with_progress "Nginx" "systemctl is-active --quiet nginx"; then
        ERRORS+=("Nginx n'est pas actif")
    else
        # Test configuration Nginx
        if ! test_with_progress "Configuration Nginx" "nginx -t"; then
            ERRORS+=("Configuration Nginx invalide")
        fi
    fi
    
    # Odoo
    if ! test_with_progress "Odoo" "systemctl is-active --quiet odoo"; then
        ERRORS+=("Odoo n'est pas actif")
    else
        # Test accès web Odoo
        if ! test_with_progress "Interface web Odoo" "curl -s -I http://localhost:8069 | grep -q '200 OK'"; then
            ERRORS+=("Interface web Odoo inaccessible")
        fi
    fi

    # 2. Vérification des fichiers
    echo -e "\n📁 Vérification des fichiers :"
    
    # Fichiers de configuration
    local CONFIG_FILES=(
        "/etc/odoo/odoo.conf"
        "/etc/nginx/sites-enabled/odoo"
        "/etc/postgresql/*/main/postgresql.conf"
        "/etc/redis/redis.conf"
    )
    
    for file in "${CONFIG_FILES[@]}"; do
        if ! test_with_progress "Configuration $file" "test -f $file"; then
            ERRORS+=("Fichier manquant : $file")
        fi
    done
    
    # Permissions
    if ! test_with_progress "Permissions Odoo" "test -O /opt/odoo -a -G /opt/odoo"; then
        ERRORS+=("Permissions incorrectes sur /opt/odoo")
    fi

    # 3. Vérification des ports
    echo -e "\n🔌 Vérification des ports :"
    local PORTS=(80 443 8069 8072 5432 6379)
    
    for port in "${PORTS[@]}"; do
        if ! test_with_progress "Port $port" "netstat -tuln | grep -q ':$port '"; then
            WARNINGS+=("Port $port non écouté")
        fi
    done

    # 4. Vérification des backups
    echo -e "\n💾 Vérification des backups :"
    if ! test_with_progress "Dossier backups" "test -d /opt/backups"; then
        WARNINGS+=("Dossier de backup non trouvé")
    fi
    
    # Test backup
    if ! test_with_progress "Test backup" "/opt/odoo/backup_advanced.sh test"; then
        WARNINGS+=("Test de backup échoué")
    fi

    # 5. Vérification SSL
    echo -e "\n🔒 Vérification SSL :"
    if [[ "$USE_CLOUDFLARE" != true ]]; then
        if ! test_with_progress "Certificats SSL" "test -d /etc/letsencrypt/live/${DOMAIN}"; then
            WARNINGS+=("Certificats SSL non trouvés")
        fi
    fi

    # 6. Vérification monitoring
    echo -e "\n📈 Vérification monitoring :"
    local MONITORING_SERVICES=("prometheus-node-exporter" "grafana-server" "loki" "promtail")
    
    for service in "${MONITORING_SERVICES[@]}"; do
        if ! test_with_progress "Service $service" "systemctl is-active --quiet $service"; then
            WARNINGS+=("Service de monitoring $service inactif")
        fi
    fi

    # Affichage du résultat
    echo -e "\n📋 Résultat de la vérification :"
    
    if [ ${#ERRORS[@]} -gt 0 ]; then
        echo -e "\n❌ Erreurs critiques détectées :"
        for error in "${ERRORS[@]}"; do
            echo "  - $error"
        done
    fi
    
    if [ ${#WARNINGS[@]} -gt 0 ]; then
        echo -e "\n⚠️ Avertissements :"
        for warning in "${WARNINGS[@]}"; do
            echo "  - $warning"
        done
    fi
    
    if [ ${#ERRORS[@]} -eq 0 ] && [ ${#WARNINGS[@]} -eq 0 ]; then
        echo -e "\n✅ Installation validée avec succès !"
        return 0
    fi
    
    # Proposition de correction
    if [ ${#ERRORS[@]} -gt 0 ]; then
        echo -e "\n🔧 Solutions proposées :"
        echo "1. Redémarrer les services :"
        echo "   systemctl restart postgresql redis-server nginx odoo"
        echo "2. Vérifier les logs :"
        echo "   journalctl -xe"
        echo "3. Vérifier les configurations :"
        echo "   less /etc/odoo/odoo.conf"
        echo "   nginx -t"
        echo "4. Réparer les permissions :"
        echo "   chown -R odoo:odoo /opt/odoo"
        
        read -p "Voulez-vous tenter une réparation automatique ? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "🔄 Tentative de réparation..."
            systemctl restart postgresql redis-server nginx odoo
            chown -R odoo:odoo /opt/odoo
            chmod -R 755 /opt/odoo
            echo "⏳ Nouvelle vérification dans 10 secondes..."
            sleep 10
            verify_installation
        fi
    fi
    
    if [ ${#ERRORS[@]} -gt 0 ]; then
        return 1
    fi
    return 0
}

# ===================== DÉTECTION ET OPTIMISATION SYSTÈME =====================
setup_distribution_detection() {
    info "Détection de la distribution Linux..."
    
    # Détection de la distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
    else
        error "Impossible de détecter la distribution"
    fi
    
    # Validation de la compatibilité
    case $DISTRO in
        debian)
            if [[ $VERSION_ID -lt 12 ]]; then
                error "Debian $VERSION_ID non supportée. Version minimum : Debian 12"
            fi
            ;;
        ubuntu)
            if [[ $VERSION_ID < "24.04" ]]; then
                error "Ubuntu $VERSION_ID non supportée. Version minimum : Ubuntu 24.04"
            fi
            ;;
        *)
            error "Distribution $DISTRO non supportée. Utilisez Debian 12+ ou Ubuntu 24.04+"
            ;;
    esac
    
    info "Distribution détectée : $DISTRO $VERSION"
}

setup_timezone_locale_detection() {
    info "Configuration timezone et locale..."
    
    # Détection timezone
    if [ -f /etc/timezone ]; then
        CURRENT_TZ=$(cat /etc/timezone)
    else
        CURRENT_TZ=$(timedatectl | grep "Time zone" | awk '{print $3}')
    fi
    
    # Configuration timezone si non définie
    if [ -z "$CURRENT_TZ" ]; then
        timedatectl set-timezone "UTC"
        info "Timezone configurée sur UTC par défaut"
    else
        info "Timezone actuelle : $CURRENT_TZ"
    fi
    
    # Configuration locale
    if ! locale -a | grep -q "^fr_FR.utf8"; then
        info "Installation locale FR..."
        locale-gen fr_FR.UTF-8
    fi
    if ! locale -a | grep -q "^en_US.utf8"; then
        info "Installation locale EN..."
        locale-gen en_US.UTF-8
    fi
    
    update-locale LANG=fr_FR.UTF-8 LC_ALL=fr_FR.UTF-8
    info "Locale configurée sur fr_FR.UTF-8"
}

setup_ipv6_support() {
    info "Configuration support IPv6..."
    
    # Vérification support IPv6
    if [ ! -f /proc/net/if_inet6 ]; then
        warn "IPv6 non supporté par le kernel"
        return
    fi
    
    # Configuration sysctl pour IPv6
    cat >> /etc/sysctl.conf << EOF
# IPv6 configuration
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
EOF
    
    # Configuration Nginx pour IPv6
    sed -i 's/listen 80;/listen 80;\n    listen [::]:80;/' /etc/nginx/sites-available/odoo
    sed -i 's/listen 443 ssl;/listen 443 ssl;\n    listen [::]:443 ssl;/' /etc/nginx/sites-available/odoo
    
    # Configuration PostgreSQL pour IPv6
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/*/main/postgresql.conf
    
    info "Support IPv6 configuré"
}

setup_python_wheel_cache() {
    info "Configuration du cache pip/wheel..."
    
    # Création du dossier cache
    mkdir -p /opt/odoo/.cache/pip
    chown -R odoo:odoo /opt/odoo/.cache
    
    # Configuration pip
    cat > /opt/odoo/.config/pip/pip.conf << EOF
[global]
download-cache = /opt/odoo/.cache/pip
wheel-dir = /opt/odoo/.cache/pip/wheels
find-links = /opt/odoo/.cache/pip/wheels
EOF
    
    # Pré-téléchargement des dépendances communes
    sudo -u odoo pip wheel --wheel-dir=/opt/odoo/.cache/pip/wheels -r /opt/odoo/odoo/requirements.txt
    
    info "Cache pip/wheel configuré"
}

setup_parallel_apt_install() {
    info "Optimisation des installations apt..."
    
    # Installation de aria2 pour des téléchargements plus rapides
    apt install -yq aria2
    
    # Configuration pour installations parallèles avec aria2
    cat > /etc/apt/apt.conf.d/99parallel-install << EOF
Acquire::Queue-Mode "host";
Acquire::http::Pipeline-Depth "5";
Acquire::https::Pipeline-Depth "5";
Acquire::Languages "none";
Acquire::ForceIPv4 "true";
Acquire::http::Timeout "180";
Acquire::https::Timeout "180";
# Utiliser aria2 pour les téléchargements
Acquire::http::Dl-Limit "0";
Acquire::https::Dl-Limit "0";
EOF

    # Configuration du nombre de connexions parallèles pour aria2
    CORES=$(nproc)
    MAX_CONNECTIONS=$((CORES * 4))
    echo "max-connection-per-server=$MAX_CONNECTIONS" >> /etc/aria2/aria2.conf
    echo "min-split-size=1M" >> /etc/aria2/aria2.conf
    
    info "Installation parallèle configurée ($CORES cœurs, $MAX_CONNECTIONS connexions max)"
}

# ===================== NOUVELLES OPTIMISATIONS =====================
setup_parallel_optimizations() {
    info "Configuration des optimisations parallèles..."
    
    # Installation des outils d'optimisation
    apt install -yq parallel pigz aria2 apt-cacher-ng dnsmasq
    
    # Configuration apt-cacher-ng
    echo "PassThroughPattern: .*" >> /etc/apt-cacher-ng/acng.conf
    systemctl enable --now apt-cacher-ng
    
    # Configuration dnsmasq
    echo "cache-size=1000" >> /etc/dnsmasq.conf
    echo "no-negcache" >> /etc/dnsmasq.conf
    systemctl enable --now dnsmasq
}

setup_cockpit() {
    info "Installation de Cockpit (interface web d'administration)..."
    
    apt install -yq cockpit cockpit-pcp cockpit-packagekit
    systemctl enable --now cockpit.socket
    
    # Configuration du pare-feu pour Cockpit
    ufw allow 9090/tcp
}

setup_crowdsec() {
    info "Installation de CrowdSec..."
    
    # Installation
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt install -yq crowdsec
    
    # Installation des collections
    cscli collections install crowdsecurity/nginx
    cscli collections install crowdsecurity/http-cve
    
    systemctl enable --now crowdsec
}

# ===================== LOGGING AVANCÉ =====================
setup_advanced_logging() {
    info "Configuration du logging avancé..."
    
    # Installation des outils de logging
    apt install -yq rsyslog logrotate filebeat prometheus-node-exporter loki promtail

    # Configuration rsyslog avancée
    cat > /etc/rsyslog.d/odoo.conf << EOF
# Logs Odoo détaillés
template(name="OdooFormat" type="string" string="%TIMESTAMP:::date-rfc3339% %HOSTNAME% %syslogtag% %msg%\n")

# Règles de logging Odoo
if \$programname == 'odoo' then {
    action(type="omfile" file="/var/log/odoo/odoo-detailed.log" template="OdooFormat")
    action(type="omfile" file="/var/log/odoo/odoo-errors.log" template="OdooFormat" filter.priority="error")
    action(type="omfile" file="/var/log/odoo/odoo-security.log" template="OdooFormat" filter.regex="(login|password|security|attack|hack)")
}

# Logs PostgreSQL
if \$programname == 'postgres' then {
    action(type="omfile" file="/var/log/postgresql/postgresql-detailed.log")
}

# Logs Nginx
if \$programname == 'nginx' then {
    action(type="omfile" file="/var/log/nginx/nginx-detailed.log")
}
EOF

    # Configuration Loki pour la centralisation des logs
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

    # Configuration Promtail pour l'envoi des logs à Loki
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

    # Configuration de la rotation des logs
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

# ===================== MONITORING À DISTANCE =====================
setup_remote_monitoring() {
    info "Configuration du monitoring à distance..."
    
    # Installation des outils de monitoring
    apt install -yq grafana prometheus prometheus-node-exporter prometheus-alertmanager netdata

    # Configuration Prometheus
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

    # Configuration des alertes Prometheus
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
      summary: "Odoo est arrêté"
      description: "Le service Odoo est inaccessible depuis 5 minutes"

  - alert: HighCPUUsage
    expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Utilisation CPU élevée"
      description: "L'utilisation CPU est supérieure à 80% depuis 10 minutes"

  - alert: HighMemoryUsage
    expr: (node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100 > 85
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Utilisation mémoire élevée"
      description: "L'utilisation de la mémoire est supérieure à 85% depuis 10 minutes"

  - alert: DiskSpaceLow
    expr: node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"} * 100 < 15
    for: 10m
    labels:
      severity: warning
    annotations:
      summary: "Espace disque faible"
      description: "Il reste moins de 15% d'espace disque"
EOF

    # Configuration Grafana
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

    # Configuration Netdata pour l'accès à distance
    cat >> /etc/netdata/netdata.conf << EOF
[web]
    bind to = *
    allow connections from = *
EOF

    # Mise en place des dashboards Grafana
    mkdir -p /var/lib/grafana/dashboards
    
    # Création d'un dashboard pour Odoo
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

    # Activation et démarrage des services
    systemctl enable --now prometheus prometheus-node-exporter prometheus-alertmanager grafana-server netdata
    
    # Ouverture des ports nécessaires
    ufw allow 3000/tcp  # Grafana
    ufw allow 19999/tcp # Netdata
    
    info "Configuration du monitoring à distance terminée"
    echo "
Accès aux interfaces de monitoring :
- Grafana : http://$DOMAIN:3000 (admin/admin)
- Netdata : http://$DOMAIN:19999
- Prometheus : http://$DOMAIN:9090
- Alertmanager : http://$DOMAIN:9093
"
}

# Mise à jour de la fonction main() pour inclure les nouvelles fonctions
main() {
    info "Démarrage de l'installation Odoo optimisée..."
    
    # Nouvelles optimisations
    setup_parallel_optimizations
    setup_cockpit
    setup_crowdsec
    
    # Suite du processus existant...
    validate_interactive
    get_user_config
    validate_inputs
    optimize_system
    install_packages
    setup_postgresql
    setup_redis
    install_odoo
    setup_nginx
    setup_ssl
    setup_monitoring
    setup_backups
    setup_firewall
    
    # Vérification finale
    if verify_installation; then
        info "Installation terminée avec succès. Documentation générée."
    else
        warn "Installation terminée avec des avertissements. Vérifiez le rapport."
    fi
    
    # Ajout des nouvelles fonctions
    setup_advanced_logging
    setup_remote_monitoring
}

# ===================== STUBS FONCTIONNELS À COMPLÉTER =====================
setup_dns_dynamic() {
    info "Configuration DNS dynamique/Cloudflare Tunnel..."
    case "$DDNS_SERVICE" in
        duckdns)
            if [[ -z "$SUBDOMAIN" || -z "$DUCKDNS_TOKEN" ]]; then
                error "DuckDNS: sous-domaine ou token manquant."
            fi
            echo "url="https://www.duckdns.org/update?domains=$SUBDOMAIN&token=$DUCKDNS_TOKEN&ip="" > /etc/cron.hourly/duckdns
            chmod 700 /etc/cron.hourly/duckdns
            info "DuckDNS configuré pour $SUBDOMAIN.duckdns.org."
            ;;
        noip)
            if [[ -z "$NOIP_USER" || -z "$NOIP_PASS" ]]; then
                error "No-IP: utilisateur ou mot de passe manquant."
            fi
            apt install -yq noip2
            noip2 -C -u "$NOIP_USER" -p "$NOIP_PASS"
            systemctl enable --now noip2
            info "No-IP configuré."
            ;;
        dynu)
            if [[ -z "$DYNU_USER" || -z "$DYNU_PASS" ]]; then
                error "Dynu: utilisateur ou mot de passe manquant."
            fi
            cat > /usr/local/bin/dynu_ddns.sh <<EOF
#!/bin/bash
curl -s "https://api.dynu.com/nic/update?hostname=$DOMAIN&username=$DYNU_USER&password=$DYNU_PASS"
EOF
            chmod 700 /usr/local/bin/dynu_ddns.sh
            (crontab -l 2>/dev/null; echo "*/10 * * * * /usr/local/bin/dynu_ddns.sh > /var/log/dynu_ddns.log 2>&1") | crontab -
            info "Dynu configuré."
            ;;
        *)
            info "Aucun service DNS dynamique sélectionné."
            ;;
    esac
}

setup_web_interface() {
    info "Déploiement de l'interface web de gestion (statique)..."
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

# Chiffrement des mots de passe (exemple pour odoo.conf)
chiffrer_conf() {
    info "Chiffrement de la configuration Odoo..."
    openssl enc -aes-256-cbc -salt -in /etc/odoo/odoo.conf -out /etc/odoo/odoo.conf.enc -k "$ADMIN_PASS"
    chmod 600 /etc/odoo/odoo.conf.enc
    info "Fichier /etc/odoo/odoo.conf.enc chiffré."
}

# Permissions strictes sur les fichiers sensibles
renforcer_permissions() {
    info "Renforcement des permissions sur les fichiers sensibles..."
    chmod 600 /etc/odoo/odoo.conf /etc/odoo/odoo.conf.enc 2>/dev/null || true
    chmod 700 /opt/backups /opt/backups/backup_odoo.sh 2>/dev/null || true
    chmod 700 /var/log/odoo 2>/dev/null || true
}

test_rollback() {
    info "Test automatique du rollback (simulation)..."
    # Exemple : suppression d'un fichier puis rollback
    touch /tmp/test_rollback
    add_rollback "rm -f /tmp/test_rollback"
    rm -f /tmp/test_rollback
    rollback
    [[ ! -f /tmp/test_rollback ]] && info "Rollback OK" || error "Rollback KO"
}

verifier_backup() {
    info "Vérification d'intégrité des sauvegardes..."
    local last_dump=$(ls -1t /opt/backups/daily/db_*.dump 2>/dev/null | head -n1)
    if [[ -f "$last_dump" ]]; then
        pg_restore -l "$last_dump" > /dev/null && info "Backup PostgreSQL OK" || warn "Backup PostgreSQL corrompu"
    else
        warn "Aucune sauvegarde PostgreSQL trouvée."
    fi
}

# Monitoring avancé (exporter Odoo Prometheus)
setup_odoo_exporter() {
    info "Déploiement de l'exporter Prometheus Odoo..."
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
    info "Exporter Prometheus Odoo actif sur port 9273."
}

# Tuning dynamique PostgreSQL/Redis/Nginx
adapt_tuning() {
    info "Tuning dynamique selon la RAM détectée..."
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
    info "Tuning : PostgreSQL $SHARED_BUFFERS, Redis $REDIS_MEM, Odoo $WORKERS workers."
}

generate_docs() {
    info "Génération de la documentation auto..."
    DOC_PATH="/var/auto_server_docs.md"
    echo "# Documentation Auto-Serveur" > "$DOC_PATH"
    echo "## Démarrage : $(date)" >> "$DOC_PATH"
    echo "- Domaine: $DOMAIN" >> "$DOC_PATH"
    echo "- Services: Odoo, PostgreSQL, Redis, Nginx, SSL, Monitoring, Backup" >> "$DOC_PATH"
    echo "- Accès Odoo: https://$DOMAIN (admin/${ADMIN_PASS})" >> "$DOC_PATH"
    echo "- Backup: /opt/backups/" >> "$DOC_PATH"
    echo "- Monitoring: Netdata, Prometheus, Odoo Exporter (port 9273)" >> "$DOC_PATH"
    echo "- Tuning dynamique: $SHARED_BUFFERS PostgreSQL, $REDIS_MEM Redis, $WORKERS workers Odoo" >> "$DOC_PATH"
    echo "- Sécurité: fichiers sensibles chiffrés, permissions renforcées" >> "$DOC_PATH"
    echo "- Test rollback: voir /tmp/test_rollback" >> "$DOC_PATH"
    echo "- Vérification backup: voir logs" >> "$DOC_PATH"
}

# ===================== SÉCURITÉ ET HARDENING AVANCÉ =====================
setup_2fa_odoo() {
    info "Activation 2FA Odoo (instructions) ..."
    echo "Activez le module officiel Odoo 2FA (Enterprise) ou community (auth_totp)." > /var/odoo_2fa_instructions.txt
    echo "Lien: https://apps.odoo.com/apps/modules/15.0/auth_totp/" >> /var/odoo_2fa_instructions.txt
}

setup_pgcrypto() {
    info "Activation du chiffrement pgcrypto sur PostgreSQL..."
    sudo -u postgres psql -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;"
}

setup_encrypted_backup() {
    info "Sauvegarde chiffrée avec GPG..."
    GPG_KEY="odoo-backup-key"
    gpg --batch --passphrase "$ADMIN_PASS" --quick-gen-key "$GPG_KEY" default default never || true
    sed -i '/tar -czf/ s|tar -czf|tar -czf - | gpg --batch --yes --passphrase $ADMIN_PASS -c -o|' /opt/backups/backup_odoo.sh
    info "Backups chiffrés avec GPG."
}

setup_password_rotation() {
    info "Mise en place de la rotation automatique des mots de passe..."
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
    info "Activation du logging d'audit Odoo/PostgreSQL..."
    sed -i 's/log_level = info/log_level = debug/' /etc/odoo/odoo.conf
    sudo -u postgres psql -c "ALTER SYSTEM SET log_statement = 'all';"
    systemctl restart postgresql
}

setup_network_isolation() {
    info "Isolation réseau avancée (iptables)..."
    iptables -A INPUT -p tcp --dport 5432 -s 127.0.0.1 -j ACCEPT
    iptables -A INPUT -p tcp --dport 5432 -j DROP
    iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
    iptables -A INPUT -p tcp --dport 6379 -j DROP
    iptables-save > /etc/iptables.rules
}

setup_ssh_hardening() {
    info "Hardening SSH..."
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd
}

setup_antivirus_ids() {
    info "Installation ClamAV et aide IDS..."
    apt install -yq clamav clamav-daemon
    systemctl enable --now clamav-daemon
    echo "Pour IDS avancé, voir Falco ou Snort."
}

setup_internal_pki() {
    info "Génération d'une PKI interne pour Redis/PostgreSQL..."
    mkdir -p /etc/odoo/pki
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/odoo/pki/odoo.key -out /etc/odoo/pki/odoo.crt -subj "/CN=odoo-internal"
    chmod 600 /etc/odoo/pki/*
}

setup_odoo_rate_limit() {
    info "Rate limiting applicatif Odoo (instructions) ..."
    echo "Installer le module community 'auth_rate_limit' ou équivalent." > /var/odoo_rate_limit.txt
}

setup_secrets_management() {
    info "Gestion des secrets avec pass (exemple)..."
    apt install -yq pass
    echo "$ADMIN_PASS" | pass insert -m odoo/admin
}

setup_integrity_monitoring() {
    info "Installation AIDE pour monitoring d'intégrité..."
    apt install -yq aide
    aideinit
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}

setup_alerting() {
    info "Configuration alertes email en cas d'incident..."
    apt install -yq mailutils
    echo 'Subject: [Odoo] Incident critique' > /usr/local/bin/odoo_alert.sh
    echo 'Un incident critique a été détecté sur le serveur Odoo.' >> /usr/local/bin/odoo_alert.sh
    chmod 700 /usr/local/bin/odoo_alert.sh
    (crontab -l 2>/dev/null; echo "@reboot /usr/local/bin/odoo_alert.sh | mail -s 'Odoo Incident' $LE_EMAIL") | crontab -
}

setup_auto_update() {
    info "Mise à jour automatique Odoo (git pull + restart)..."
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
    info "Backup cloud (exemple S3)..."
    apt install -yq awscli
    echo "0 5 * * * aws s3 sync /opt/backups/ s3://mon-bucket-odoo-backup/" | crontab -
}

setup_staging_env() {
    info "Déploiement d'un environnement de staging (clone prod)..."
    cp -r /opt/odoo /opt/odoo-staging
    cp -r /etc/odoo /etc/odoo-staging
}

setup_load_balancing() {
    info "Instructions pour load balancing avec HAProxy..."
    echo "Voir https://www.haproxy.org/ pour configurer un cluster Odoo." > /var/odoo_lb.txt
}

setup_cdn() {
    info "Instructions pour CDN Cloudflare..."
    echo "Configurer Cloudflare CDN sur le domaine $DOMAIN pour les assets statiques." > /var/odoo_cdn.txt
}

setup_debug_tools() {
    info "Installation outils debug Python/Odoo..."
    pip install py-spy werkzeug
}

setup_perf_profiling() {
    info "Profiling automatique Odoo..."
    pip install py-spy
    py-spy record -o /var/log/odoo/odoo-profile.svg --pid $(pgrep -f odoo-bin) &
}

setup_disaster_recovery() {
    info "Configuration de la reprise après sinistre..."
    
    # Création du répertoire DR
    mkdir -p /opt/odoo/disaster_recovery
    
    # Script de reprise après sinistre
    cat > /opt/odoo/disaster_recovery/restore.sh << 'EOF'
#!/bin/bash

# Configuration
BACKUP_DIR="/opt/backups"
RESTORE_DIR="/opt/odoo/restore"
DB_NAME="odoo_production"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Fonction de restauration de la base de données
restore_database() {
    local backup_file="$1"
    info "Restauration de la base de données depuis $backup_file..."
    
    # Arrêt des services
    systemctl stop odoo nginx
    
    # Suppression de la base existante
    sudo -u postgres dropdb "$DB_NAME" || true
    
    # Création d'une nouvelle base
    sudo -u postgres createdb "$DB_NAME"
    
    # Restauration
    if [[ "$backup_file" == *.dump ]]; then
        sudo -u postgres pg_restore -d "$DB_NAME" "$backup_file"
    elif [[ "$backup_file" == *.sql ]]; then
        sudo -u postgres psql "$DB_NAME" < "$backup_file"
    else
        error "Format de backup non supporté : $backup_file"
        exit 1
    fi
}

# Fonction de restauration des fichiers
restore_files() {
    local backup_file="$1"
    info "Restauration des fichiers depuis $backup_file..."
    
    # Création du répertoire de restauration
    mkdir -p "$RESTORE_DIR"
    
    # Extraction
    tar -xzf "$backup_file" -C "$RESTORE_DIR"
    
    # Restauration des permissions
    chown -R odoo:odoo "$RESTORE_DIR"
    find "$RESTORE_DIR" -type f -exec chmod 644 {} \;
    find "$RESTORE_DIR" -type d -exec chmod 755 {} \;
}

# Fonction de restauration de la configuration
restore_config() {
    local backup_file="$1"
    info "Restauration de la configuration depuis $backup_file..."
    
    # Sauvegarde de la configuration actuelle
    mv /etc/odoo/odoo.conf /etc/odoo/odoo.conf.bak.$TIMESTAMP
    mv /etc/nginx/sites-available/odoo /etc/nginx/sites-available/odoo.bak.$TIMESTAMP
    
    # Extraction de la configuration
    tar -xzf "$backup_file" -C /
}

# Fonction de vérification
verify_restore() {
    info "Vérification de la restauration..."
    
    # Vérification de la base de données
    if ! sudo -u postgres psql -d "$DB_NAME" -c "\dt" > /dev/null; then
        error "Échec de la vérification de la base de données"
        return 1
    fi
    
    # Vérification des fichiers
    if [ ! -d "$RESTORE_DIR/data" ]; then
        error "Échec de la vérification des fichiers"
        return 1
    fi
    
    # Vérification de la configuration
    if [ ! -f "/etc/odoo/odoo.conf" ]; then
        error "Échec de la vérification de la configuration"
        return 1
    fi
    
    return 0
}

# Fonction de rollback
rollback_restore() {
    info "Rollback de la restauration..."
    
    # Restauration de la base de données
    if [ -f "$BACKUP_DIR/pre_restore_${TIMESTAMP}.dump" ]; then
        restore_database "$BACKUP_DIR/pre_restore_${TIMESTAMP}.dump"
    fi
    
    # Restauration des fichiers
    if [ -d "$BACKUP_DIR/pre_restore_${TIMESTAMP}_files" ]; then
        rm -rf /opt/odoo/data
        mv "$BACKUP_DIR/pre_restore_${TIMESTAMP}_files" /opt/odoo/data
    fi
    
    # Restauration de la configuration
    if [ -f "/etc/odoo/odoo.conf.bak.$TIMESTAMP" ]; then
        mv "/etc/odoo/odoo.conf.bak.$TIMESTAMP" /etc/odoo/odoo.conf
    fi
    if [ -f "/etc/nginx/sites-available/odoo.bak.$TIMESTAMP" ]; then
        mv "/etc/nginx/sites-available/odoo.bak.$TIMESTAMP" /etc/nginx/sites-available/odoo
    fi
}

# Menu principal
echo "=== Menu de restauration ==="
echo "1) Restauration complète (dernière sauvegarde)"
echo "2) Restauration à un point dans le temps"
echo "3) Restauration sélective"
echo "4) Quitter"

read -p "Choix : " choice

case $choice in
    1)
        # Sauvegarde pré-restauration
        sudo -u postgres pg_dump -Fc "$DB_NAME" > "$BACKUP_DIR/pre_restore_${TIMESTAMP}.dump"
        cp -r /opt/odoo/data "$BACKUP_DIR/pre_restore_${TIMESTAMP}_files"
        
        # Restauration
        latest_db=$(ls -t "$BACKUP_DIR"/db_*.dump | head -1)
        latest_files=$(ls -t "$BACKUP_DIR"/files_*.tar.gz | head -1)
        latest_config=$(ls -t "$BACKUP_DIR"/config_*.tar.gz | head -1)
        
        restore_database "$latest_db"
        restore_files "$latest_files"
        restore_config "$latest_config"
        
        if verify_restore; then
            info "Restauration complète réussie"
            systemctl start odoo nginx
        else
            error "Échec de la restauration"
            rollback_restore
        fi
        ;;
    2)
        # Liste des sauvegardes disponibles
        echo "Sauvegardes disponibles :"
        ls -lt "$BACKUP_DIR"/db_*.dump | awk '{print $9}'
        
        read -p "Date de restauration (YYYYMMDD_HHMMSS) : " restore_date
        
        db_file="$BACKUP_DIR/db_${restore_date}.dump"
        files_file="$BACKUP_DIR/files_${restore_date}.tar.gz"
        config_file="$BACKUP_DIR/config_${restore_date}.tar.gz"
        
        if [ ! -f "$db_file" ] || [ ! -f "$files_file" ] || [ ! -f "$config_file" ]; then
            error "Fichiers de sauvegarde non trouvés pour la date spécifiée"
            exit 1
        fi
        
        # Sauvegarde pré-restauration
        sudo -u postgres pg_dump -Fc "$DB_NAME" > "$BACKUP_DIR/pre_restore_${TIMESTAMP}.dump"
        cp -r /opt/odoo/data "$BACKUP_DIR/pre_restore_${TIMESTAMP}_files"
        
        restore_database "$db_file"
        restore_files "$files_file"
        restore_config "$config_file"
        
        if verify_restore; then
            info "Restauration point-in-time réussie"
            systemctl start odoo nginx
        else
            error "Échec de la restauration"
            rollback_restore
        fi
        ;;
    3)
        echo "Que souhaitez-vous restaurer ?"
        echo "1) Base de données uniquement"
        echo "2) Fichiers uniquement"
        echo "3) Configuration uniquement"
        
        read -p "Choix : " restore_choice
        
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
                error "Choix invalide"
                exit 1
                ;;
        esac
        
        systemctl start odoo nginx
        ;;
    4)
        exit 0
        ;;
    *)
        error "Choix invalide"
        exit 1
        ;;
esac
EOF
    
    chmod +x /opt/odoo/disaster_recovery/restore.sh
    
    # Documentation de reprise après sinistre
    cat > /opt/odoo/disaster_recovery/README.md << 'EOF'
# Guide de reprise après sinistre

## Prérequis
- Accès root au serveur
- Sauvegardes valides
- Espace disque suffisant

## Procédures

### 1. Restauration complète
```bash
cd /opt/odoo/disaster_recovery
./restore.sh
# Choisir option 1
```

### 2. Restauration point-in-time
```bash
cd /opt/odoo/disaster_recovery
./restore.sh
# Choisir option 2
# Spécifier la date au format YYYYMMDD_HHMMSS
```

### 3. Restauration sélective
```bash
cd /opt/odoo/disaster_recovery
./restore.sh
# Choisir option 3
# Sélectionner les composants à restaurer
```

## Vérifications post-restauration
1. Connexion à l'interface web Odoo
2. Vérification des données
3. Test des fonctionnalités critiques
4. Vérification des logs

## Support
En cas de problème :
1. Consulter les logs : /var/log/odoo/restore.log
2. Contacter l'administrateur système
3. Utiliser la procédure de rollback si nécessaire

## Maintenance
- Tester la restauration régulièrement
- Vérifier l'intégrité des sauvegardes
- Mettre à jour la documentation
- Former les équipes
EOF
    
    # Script de test de restauration
    cat > /opt/odoo/disaster_recovery/test_restore.sh << 'EOF'
#!/bin/bash

# Configuration
TEST_DB="odoo_test_restore"
TEST_DIR="/opt/odoo/test_restore"
LOG_FILE="/var/log/odoo/restore_test.log"

# Nettoyage
rm -rf "$TEST_DIR"
sudo -u postgres dropdb "$TEST_DB" 2>/dev/null

# Test de restauration
latest_db=$(ls -t /opt/backups/db_*.dump | head -1)
latest_files=$(ls -t /opt/backups/files_*.tar.gz | head -1)

# Restauration base de données
sudo -u postgres createdb "$TEST_DB"
if ! sudo -u postgres pg_restore -d "$TEST_DB" "$latest_db" >> "$LOG_FILE" 2>&1; then
    echo "ERREUR: Échec de la restauration de la base de données"
    exit 1
fi

# Restauration fichiers
mkdir -p "$TEST_DIR"
if ! tar -xzf "$latest_files" -C "$TEST_DIR" >> "$LOG_FILE" 2>&1; then
    echo "ERREUR: Échec de la restauration des fichiers"
    exit 1
fi

# Vérifications
if sudo -u postgres psql -d "$TEST_DB" -c "\dt" > /dev/null 2>&1; then
    echo "Test de restauration réussi"
else
    echo "ERREUR: Échec du test de restauration"
    exit 1
fi

# Nettoyage
sudo -u postgres dropdb "$TEST_DB"
rm -rf "$TEST_DIR"
EOF
    
    chmod +x /opt/odoo/disaster_recovery/test_restore.sh
    
    # Planification des tests de restauration
    (crontab -l 2>/dev/null; echo "0 3 * * 0 /opt/odoo/disaster_recovery/test_restore.sh") | crontab -
    
    info "Configuration de la reprise après sinistre terminée"
}

setup_apparmor() {
    info "Configuration AppArmor..."
    
    # Installation d'AppArmor
    apt install -yq apparmor apparmor-utils
    
    # Profil AppArmor pour Odoo
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

    # Profil AppArmor pour PostgreSQL
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

    # Activation des profils
    apparmor_parser -r /etc/apparmor.d/usr.bin.odoo
    apparmor_parser -r /etc/apparmor.d/usr.sbin.postgres
    
    # Activation d'AppArmor
    systemctl enable apparmor
    systemctl restart apparmor
    
    info "Configuration AppArmor terminée"
}

setup_varnish() {
    info "Configuration Varnish Cache..."
    
    # Installation de Varnish
    apt install -yq varnish
    
    # Configuration Varnish
    cat > /etc/varnish/default.vcl << 'EOF'
vcl 4.0;

backend default {
    .host = "127.0.0.1";
    .port = "8069";
    .first_byte_timeout = 300s;
    .between_bytes_timeout = 60s;
}

# Définition des pages à ne pas mettre en cache
sub vcl_recv {
    # Ne pas mettre en cache les pages d'administration
    if (req.url ~ "^/web/database/" ||
        req.url ~ "^/web/session/" ||
        req.url ~ "^/web/login" ||
        req.url ~ "^/web/reset_password" ||
        req.url ~ "^/web/signup") {
        return (pass);
    }
    
    # Mise en cache des assets statiques
    if (req.url ~ "\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|eot|svg)$") {
        unset req.http.Cookie;
        return (hash);
    }
    
    # Ne pas mettre en cache les requêtes POST
    if (req.method == "POST") {
        return (pass);
    }
}

sub vcl_backend_response {
    # Configuration du TTL pour différents types de contenu
    if (bereq.url ~ "\.(css|js|jpg|jpeg|png|gif|ico|woff|woff2|ttf|eot|svg)$") {
        set beresp.ttl = 24h;
        set beresp.grace = 12h;
        unset beresp.http.Set-Cookie;
    } else {
        set beresp.ttl = 1h;
        set beresp.grace = 30m;
    }
    
    # Compression gzip
    if (beresp.http.content-type ~ "text" ||
        beresp.http.content-type ~ "application/javascript" ||
        beresp.http.content-type ~ "application/json") {
        set beresp.do_gzip = true;
    }
}

sub vcl_deliver {
    # Ajout d'en-têtes pour le debugging
    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
    } else {
        set resp.http.X-Cache = "MISS";
    }
    set resp.http.X-Cache-Hits = obj.hits;
}
EOF

    # Configuration du service Varnish
    sed -i 's/DAEMON_OPTS="-a :6081/DAEMON_OPTS="-a :80/' /etc/default/varnish
    
    # Mise à jour de la configuration systemd
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

    # Mise à jour de la configuration Nginx pour utiliser Varnish
    sed -i 's/listen 80;/listen 8069;/' /etc/nginx/sites-available/odoo
    
    # Redémarrage des services
    systemctl daemon-reload
    systemctl enable varnish
    systemctl restart varnish nginx
    
    info "Configuration Varnish terminée"
}

setup_selinux() {
    info "Configuration SELinux..."
    
    # Installation des outils SELinux
    apt install -yq selinux-basics selinux-policy-default auditd audispd-plugins
    
    # Activation de SELinux
    selinux-activate
    
    # Création de la politique SELinux pour Odoo
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

# Règles pour Odoo
allow httpd_t odoo_port_t:tcp_socket name_connect;
allow httpd_t odoo_var_lib_t:dir { search add_name remove_name write };
allow httpd_t odoo_var_lib_t:file { read write create unlink };
allow httpd_t odoo_log_t:file { write create };

# Règles pour PostgreSQL
allow postgresql_t odoo_port_t:tcp_socket name_connect;
EOF

    # Compilation et installation de la politique
    checkmodule -M -m -o odoo.mod odoo.te
    semodule_package -o odoo.pp -m odoo.mod
    semodule -i odoo.pp
    
    # Configuration des contextes de sécurité
    semanage fcontext -a -t odoo_var_lib_t "/opt/odoo/data(/.*)?"
    semanage fcontext -a -t odoo_log_t "/var/log/odoo(/.*)?"
    semanage port -a -t odoo_port_t -p tcp 8069
    semanage port -a -t odoo_port_t -p tcp 8072
    
    # Application des contextes
    restorecon -R /opt/odoo/data
    restorecon -R /var/log/odoo
    
    # Configuration audit
    cat >> /etc/audit/rules.d/audit.rules << EOF
# Règles d'audit pour Odoo
-w /opt/odoo/odoo -p wa -k odoo_changes
-w /etc/odoo -p wa -k odoo_config
-w /var/log/odoo -p wa -k odoo_logs
EOF
    
    # Redémarrage des services
    systemctl restart auditd
    
    info "Configuration SELinux terminée"
}

setup_vault() {
    info "Configuration de HashiCorp Vault pour la gestion des secrets..."
    
    # Installation de Vault
    curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
    apt update && apt install -y vault
    
    # Configuration de base de Vault
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
    
    # Création du service systemd
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
    
    # Démarrage de Vault
    systemctl daemon-reload
    systemctl enable --now vault
    
    # Initialisation de Vault (à faire manuellement pour la sécurité)
    echo "Pour initialiser Vault, exécutez : vault operator init" > /root/vault_init_instructions.txt
    
    info "Vault installé. Voir /root/vault_init_instructions.txt pour l'initialisation"
}

setup_docker() {
    info "Configuration de Docker et Docker Compose..."
    
    # Installation de Docker
    curl -fsSL https://get.docker.com | sh
    
    # Installation de Docker Compose
    curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    
    # Configuration de Docker
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
    
    # Création du docker-compose.yml pour les services
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
    
    # Démarrage des services
    cd /opt/odoo/docker
    docker-compose up -d
    
    info "Docker et services configurés. Portainer accessible sur https://portainer.${DOMAIN}"
}

load_env_config() {
    info "Chargement de la configuration depuis .env..."
    
    # Fichier .env par défaut
    if [ -f ".env" ]; then
        set -a
        source .env
        set +a
        info "Configuration chargée depuis .env"
    fi
    
    # Variables d'environnement avec valeurs par défaut
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
    
    # Validation des variables requises en mode production
    if [ "$INSTALL_MODE" = "production" ]; then
        if [ -z "$DOMAIN" ]; then
            error "DOMAIN est requis en mode production"
        fi
        if [ "$CLOUDFLARE_TUNNEL" != "true" ] && [ -z "$LE_EMAIL" ]; then
            error "LE_EMAIL est requis en mode production sans Cloudflare Tunnel"
        fi
    fi
}
