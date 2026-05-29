#!/bin/bash
# ============================================================
#  GenieACS Multi-Instance — Tambah Instance Baru
#  Support: Ubuntu 20.04 / 22.04 / 24.04 / RHEL / CentOS
#  By RadFast Bill
#  Usage: sudo bash add-instance.sh [username]
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash add-instance.sh"

APP_DIR="/opt/genieacs-app"
INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"
REPO_DIR="/opt/radfast_acs"

[[ ! -d "$APP_DIR" ]]       && error "App tidak ada di $APP_DIR. Jalankan setup-system.sh dulu!"
[[ ! -d "$INSTANCES_DIR" ]] && error "Folder instances tidak ada. Jalankan setup-system.sh dulu!"

# ── Input username ───────────────────────────────────────────
if [[ -n "${1:-}" ]]; then
    USERNAME="$1"
else
    echo ""
    read -rp "$(echo -e "${CYAN}[INPUT]${NC} Nama instance/user (huruf kecil, tanpa spasi): ")" USERNAME
fi

USERNAME=$(echo "$USERNAME" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
[[ -z "$USERNAME" ]]                       && error "Username tidak valid! Hanya huruf kecil, angka, - dan _"
[[ ${#USERNAME} -lt 2 ]]                   && error "Username minimal 2 karakter!"
[[ -d "$INSTANCES_DIR/$USERNAME" ]]        && error "Instance '$USERNAME' sudah ada! Gunakan nama lain."

# ── Cari port yang benar-benar bebas ─────────────────────────
all_used_ports() {
    if [[ -d "$INSTANCES_DIR" ]]; then
        grep -rh "_PORT=" "$INSTANCES_DIR/"*"/.env" 2>/dev/null \
            | grep -oP '=\K[0-9]+$' || true
    fi
    ss -tlnp 2>/dev/null | grep -oP '(?<=:)\d+(?= )' || \
    netstat -tlnp 2>/dev/null | grep -oP ':\K[0-9]+(?= )' || true
}

USED_PORTS=$(all_used_ports | sort -un)

is_used() { echo "$USED_PORTS" | grep -qx "$1"; }

next_free_from() {
    local p=$1
    while is_used "$p"; do p=$((p + 1)); done
    USED_PORTS=$(printf "%s\n%s" "$USED_PORTS" "$p" | sort -un)
    echo "$p"
}

# Port public (yang diakses user)
UI_PORT=$(next_free_from 3001)
CWMP_PORT=$(next_free_from 7548)
NBI_PORT=$(next_free_from 7558)
FS_PORT=$(next_free_from 7568)

# Port internal GenieACS UI (dipakai logo-proxy, user tidak akses langsung)
# Pakai rentang 13000+ supaya tidak bentrok
UI_INTERNAL=$(next_free_from $((UI_PORT + 10000)))

# ── Secret & info ────────────────────────────────────────────
JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || \
             od -An -tx1 /dev/urandom | head -2 | tr -d ' \n' | cut -c1-64)
ADMIN_TOKEN=$(openssl rand -hex 16 2>/dev/null || \
              od -An -tx1 /dev/urandom | head -1 | tr -d ' \n' | cut -c1-32)

# Secret path untuk akses NBI (REST API) lewat port UI publik.
# Hanya yang tahu path ini yang bisa hit /devices dkk. Tanpa path → 404 (jatuh ke UI).
NBI_GATE_KEY=$(openssl rand -hex 20 2>/dev/null || \
               od -An -tx1 /dev/urandom | head -2 | tr -d ' \n' | cut -c1-40)
NBI_GATE_PATH="/_acs-${NBI_GATE_KEY}"

DB_NAME="genieacs_${USERNAME}"
INST_DIR="$INSTANCES_DIR/$USERNAME"
LOGO_BASE="$INST_DIR/logo/custom-logo"

# Deteksi IP server
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}') || \
SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+') || \
SERVER_IP="127.0.0.1"

# ── Konfirmasi ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}  Instance baru akan dibuat:${NC}"
echo -e "  User     : ${CYAN}$USERNAME${NC}"
echo -e "  UI       : ${CYAN}:$UI_PORT${NC}    ← Dashboard Web (buka di browser)"
echo -e "  CWMP     : ${CYAN}:$CWMP_PORT${NC}    ← Port device TR-069/ONU/router"
echo -e "  NBI      : ${CYAN}:$NBI_PORT${NC}    ← REST API untuk integrasi sistem"
echo -e "  FS       : ${CYAN}:$FS_PORT${NC}    ← File Server firmware/config"
echo -e "  Database : ${CYAN}$DB_NAME${NC}"
echo -e "  Folder   : ${CYAN}$INST_DIR${NC}"
echo ""
read -rp "$(echo -e "${YELLOW}Lanjutkan? [Y/n]: ${NC}")" CONFIRM
CONFIRM="${CONFIRM:-Y}"
[[ ! "$CONFIRM" =~ ^[Yy]$ ]] && echo "Dibatalkan." && exit 0

# ── Buat folder instance ─────────────────────────────────────
mkdir -p "$INST_DIR" "$INST_DIR/logo"

# ── Tulis .env ───────────────────────────────────────────────
cat > "$INST_DIR/.env" <<EOF
# GenieACS instance: ${USERNAME}
# Generated: $(date '+%Y-%m-%d %H:%M:%S')

# Database
GENIEACS_MONGODB_CONNECTION_URL=mongodb://127.0.0.1:27017/${DB_NAME}

# Port internal GenieACS (tidak langsung diakses user)
GENIEACS_CWMP_PORT=${CWMP_PORT}
GENIEACS_NBI_PORT=${NBI_PORT}
GENIEACS_FS_PORT=${FS_PORT}
GENIEACS_UI_PORT=${UI_INTERNAL}
GENIEACS_FS_HOSTNAME=${SERVER_IP}
GENIEACS_UI_JWT_SECRET=${JWT_SECRET}

# Bind NBI ke localhost saja. NBI = REST API TANPA auth bawaan.
# Port NBI TIDAK dibuka ke publik; akses publik HANYA lewat secret path di
# port UI (logo-proxy meneruskan {RADFAST_NBI_GATE_PATH}/... → 127.0.0.1:${NBI_PORT}).
# Billing/GoRadius pakai URL: http://${SERVER_IP}:${UI_PORT}${NBI_GATE_PATH}
# Catatan: FS sengaja TIDAK di-localhost agar firmware OTA tetap jalan;
# amankan FS via firewall/VPN sesuai kebutuhan.
GENIEACS_NBI_INTERFACE=127.0.0.1

# Logo Proxy (akses publik UI via proxy)
RADFAST_PROXY_PORT=${UI_PORT}
RADFAST_UI_INTERNAL=${UI_INTERNAL}
RADFAST_NBI_GATE_PATH=${NBI_GATE_PATH}
RADFAST_LOGO_FILE=${LOGO_BASE}
RADFAST_ADMIN_TOKEN=${ADMIN_TOKEN}
EOF
success ".env dibuat"

# ── Import MongoDB ───────────────────────────────────────────
CONF_DIR="$APP_DIR/conf-acs"
if [[ -d "$CONF_DIR" ]]; then
    if command -v mongorestore &>/dev/null; then
        info "Import MongoDB → database: $DB_NAME..."
        mongorestore --db "$DB_NAME" --drop "$CONF_DIR" 2>&1 \
            | grep -E "done|error|finish|inserted|documents" || true
        success "MongoDB diimport ke $DB_NAME"
    else
        warn "mongorestore tidak ditemukan — skip import MongoDB"
    fi
else
    warn "conf-acs tidak ditemukan di $APP_DIR — skip import MongoDB"
fi

# ── Cari node & proxy script ─────────────────────────────────
NODE_BIN=$(command -v node 2>/dev/null || echo "/usr/bin/node")
[[ ! -f "$NODE_BIN" ]] && error "node binary tidak ditemukan!"

# Cari logo-proxy.js
PROXY_SCRIPT=""
for loc in "$REPO_DIR/logo-proxy.js" "$(dirname "$0")/logo-proxy.js" "/opt/radfast_acs/logo-proxy.js"; do
    [[ -f "$loc" ]] && PROXY_SCRIPT="$loc" && break
done
[[ -z "$PROXY_SCRIPT" ]] && warn "logo-proxy.js tidak ditemukan — fitur upload logo tidak aktif"

# ── Buat systemd services ────────────────────────────────────
info "Membuat systemd services..."

for SVC in cwmp fs nbi ui; do
    case $SVC in
        cwmp) PORT=$CWMP_PORT ;;
        fs)   PORT=$FS_PORT ;;
        nbi)  PORT=$NBI_PORT ;;
        ui)   PORT=$UI_INTERNAL ;;
    esac
    cat > "/etc/systemd/system/genieacs-${USERNAME}-${SVC}.service" <<EOF
[Unit]
Description=GenieACS ${SVC^^} — ${USERNAME} (port ${PORT})
After=network.target mongod.service
Wants=mongod.service

[Service]
Type=simple
User=root
WorkingDirectory=${INST_DIR}
EnvironmentFile=${INST_DIR}/.env
ExecStart=${NODE_BIN} ${APP_DIR}/bin/genieacs-${SVC}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=genieacs-${USERNAME}-${SVC}

[Install]
WantedBy=multi-user.target
EOF
done

# Proxy publik + logo upload sekarang SELALU pakai multi-proxy.
# Tidak ada lagi service genieacs-<user>-proxy per instance.
[[ -z "$PROXY_SCRIPT" ]] && error "logo-proxy.js tidak ditemukan — multi-proxy tidak bisa berjalan"

MULTI_SCRIPT="$REPO_DIR/multi-proxy.js"
[[ ! -f "$MULTI_SCRIPT" ]] && error "multi-proxy.js tidak ditemukan di $MULTI_SCRIPT"

MULTI_SERVICE_FILE="/etc/systemd/system/genieacs-multi-proxy.service"
info "Menulis service genieacs-multi-proxy (mode wajib)..."
cat > "$MULTI_SERVICE_FILE" <<EOF
[Unit]
Description=RadFast ACS Multi-Instance Logo Proxy
After=network.target

[Service]
Type=simple
Environment=NODE_ENV=production
Environment=RADFAST_INSTANCES_DIR=${INSTANCES_DIR}
Environment=RADFAST_REGISTRY=${REGISTRY}
Environment=RADFAST_PROXY_SCRIPT=${PROXY_SCRIPT}
ExecStart=${NODE_BIN} ${MULTI_SCRIPT}
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=genieacs-multi-proxy
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
success "Service genieacs-multi-proxy siap"

# Bersihkan SEMUA service proxy per-instance lama (legacy mode)
info "Membersihkan proxy per-instance lama..."
if [[ -f "$REGISTRY" ]]; then
    while IFS= read -r LINE; do
        [[ -z "$LINE" ]] && continue
        OLD_USER="$(awk '{print $1}' <<< "$LINE")"
        [[ -z "$OLD_USER" ]] && continue
        OLD_SVC="genieacs-${OLD_USER}-proxy"
        systemctl stop "$OLD_SVC" &>/dev/null 2>&1 || true
        systemctl disable "$OLD_SVC" &>/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/${OLD_SVC}.service"
    done < "$REGISTRY"
fi

# Bersihkan orphan unit file yang mungkin tidak ada di registry
for UNIT_FILE in /etc/systemd/system/genieacs-*-proxy.service; do
    [[ -e "$UNIT_FILE" ]] || continue
    UNIT_NAME="$(basename "$UNIT_FILE" .service)"
    [[ "$UNIT_NAME" == "genieacs-multi-proxy" ]] && continue
    systemctl stop "$UNIT_NAME" &>/dev/null 2>&1 || true
    systemctl disable "$UNIT_NAME" &>/dev/null 2>&1 || true
    rm -f "$UNIT_FILE"
done

systemctl daemon-reload
systemctl enable genieacs-multi-proxy &>/dev/null 2>&1 || true
success "Systemd services dibuat (multi-proxy only)"

# ── Enable & Start services ──────────────────────────────────
info "Menjalankan services..."
ALL_OK=true
SERVICES="cwmp fs nbi ui"

for SVC in $SERVICES; do
    SVCNAME="genieacs-${USERNAME}-${SVC}"
    systemctl enable "$SVCNAME" &>/dev/null 2>&1 || true
    if systemctl start "$SVCNAME" 2>/dev/null; then
        sleep 1
        if systemctl is-active --quiet "$SVCNAME" 2>/dev/null; then
            success "$SVCNAME  ✓"
        else
            warn "$SVCNAME  ✗ (cek: journalctl -u $SVCNAME -n 20)"
            ALL_OK=false
        fi
    else
        warn "$SVCNAME  ✗ gagal start"
        ALL_OK=false
    fi
done

# ── Simpan ke registry ───────────────────────────────────────
touch "$REGISTRY"
grep -v "^${USERNAME} " "$REGISTRY" > "${REGISTRY}.tmp" 2>/dev/null \
    && mv "${REGISTRY}.tmp" "$REGISTRY" || rm -f "${REGISTRY}.tmp"
echo "${USERNAME} UI=${UI_PORT} CWMP=${CWMP_PORT} NBI=${NBI_PORT} FS=${FS_PORT} DB=${DB_NAME} IP=${SERVER_IP} DATE=$(date '+%Y-%m-%d')" \
    >> "$REGISTRY"

# Restart multi-proxy setelah registry update supaya instance baru langsung aktif
if systemctl restart genieacs-multi-proxy 2>/dev/null; then
    success "genieacs-multi-proxy direstart → instance '${USERNAME}' aktif di port ${UI_PORT}"
else
    warn "Gagal restart genieacs-multi-proxy (cek: journalctl -u genieacs-multi-proxy -n 50)"
    ALL_OK=false
fi

# ── Ringkasan ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}============================================================${NC}"
if $ALL_OK; then
    echo -e "${GREEN}${BOLD}   Instance '${USERNAME}' BERHASIL dibuat & berjalan!${NC}"
else
    echo -e "${YELLOW}${BOLD}   Instance '${USERNAME}' dibuat (ada service gagal — cek log)${NC}"
fi
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo ""
echo -e "  ${BOLD}Akses & Info Port:${NC}"
echo -e "  ┌──────────────────────────────────────────────────────┐"
echo -e "  │ UI   (Dashboard Web)                                 │"
echo -e "  │   → ${CYAN}http://${SERVER_IP}:${UI_PORT}${NC}"
echo -e "  │   Buka di browser untuk kelola device                │"
echo -e "  ├──────────────────────────────────────────────────────┤"
echo -e "  │ 🖼  Upload Logo (tanpa terminal)                     │"
echo -e "  │   → ${CYAN}http://${SERVER_IP}:${UI_PORT}/__admin/logo${NC}"
echo -e "  │   Token: ${YELLOW}${ADMIN_TOKEN}${NC}"
echo -e "  ├──────────────────────────────────────────────────────┤"
echo -e "  │ CWMP  (TR-069 Device/CPE)     port ${CWMP_PORT}               │"
echo -e "  │   ACS URL device: http://${SERVER_IP}:${CWMP_PORT}    │"
echo -e "  ├──────────────────────────────────────────────────────┤"
echo -e "  │ NBI   (REST API / Integrasi)                          │"
echo -e "  │   Port ${NBI_PORT} di-LOCK ke localhost (tidak publik).      │"
echo -e "  │   Secure URL (untuk billing/GoRadius):               │"
echo -e "  │   → ${CYAN}http://${SERVER_IP}:${UI_PORT}${NBI_GATE_PATH}${NC}"
echo -e "  ├──────────────────────────────────────────────────────┤"
echo -e "  │ FS    (File Server firmware)   port ${FS_PORT}               │"
echo -e "  └──────────────────────────────────────────────────────┘"
echo -e "  ${YELLOW}⚠  Simpan Secure URL NBI di atas — isikan ke GoRadius Settings > Umum > GenieACS API URL.${NC}"
echo ""
echo -e "  Database : ${DB_NAME}"
echo -e "  Folder   : ${INST_DIR}"
echo ""
echo -e "  ${BOLD}Manage:${NC}"
echo -e "  ${YELLOW}systemctl status genieacs-${USERNAME}-ui${NC}"
echo -e "  ${YELLOW}journalctl -u genieacs-multi-proxy -f${NC}"
echo -e "  ${YELLOW}sudo bash /opt/radfast_acs/remove-instance.sh ${USERNAME}${NC}"
echo "============================================================"
