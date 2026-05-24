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
[[ -z "$USERNAME" ]]            && error "Username tidak valid! Hanya huruf kecil, angka, - dan _"
[[ ${#USERNAME} -lt 2 ]]        && error "Username minimal 2 karakter!"
[[ -d "$INSTANCES_DIR/$USERNAME" ]] && error "Instance '$USERNAME' sudah ada! Gunakan nama lain."

# ── Cari port yang benar-benar bebas ─────────────────────────
# Kumpulkan semua port yang sudah dipakai (dari .env + sistem)
all_used_ports() {
    # Port dari instances yang sudah ada
    if [[ -d "$INSTANCES_DIR" ]]; then
        grep -rh "_PORT=" "$INSTANCES_DIR/"*"/.env" 2>/dev/null \
            | grep -oP '=\K[0-9]+$' || true
    fi
    # Port yang sedang listen di sistem
    ss -tlnp 2>/dev/null | grep -oP '(?<=:)\d+(?= )' || \
    netstat -tlnp 2>/dev/null | grep -oP ':\K[0-9]+(?= )' || true
}

# Build set port yang dipakai
USED_PORTS=$(all_used_ports | sort -un)

is_used() {
    echo "$USED_PORTS" | grep -qx "$1"
}

next_free_from() {
    local p=$1
    while is_used "$p"; do p=$((p + 1)); done
    # Tandai sebagai sudah dipakai supaya 4 port tidak ambil nomor sama
    USED_PORTS=$(printf "%s\n%s" "$USED_PORTS" "$p" | sort -un)
    echo "$p"
}

UI_PORT=$(next_free_from 3001)
CWMP_PORT=$(next_free_from 7548)
NBI_PORT=$(next_free_from 7558)
FS_PORT=$(next_free_from 7568)

# ── JWT secret & info ────────────────────────────────────────
JWT_SECRET=$(openssl rand -hex 32 2>/dev/null || \
             od -An -tx1 /dev/urandom | head -2 | tr -d ' \n' | cut -c1-64)

DB_NAME="genieacs_${USERNAME}"
INST_DIR="$INSTANCES_DIR/$USERNAME"

# Deteksi IP server (fallback chain)
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}') || \
SERVER_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K[\d.]+') || \
SERVER_IP="127.0.0.1"

# ── Konfirmasi ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}  Instance baru akan dibuat:${NC}"
echo -e "  User     : ${CYAN}$USERNAME${NC}"
echo -e "  UI Port  : ${CYAN}$UI_PORT${NC}   → http://$SERVER_IP:$UI_PORT"
echo -e "  CWMP Port: ${CYAN}$CWMP_PORT${NC}"
echo -e "  NBI Port : ${CYAN}$NBI_PORT${NC}"
echo -e "  FS Port  : ${CYAN}$FS_PORT${NC}"
echo -e "  Database : ${CYAN}$DB_NAME${NC}"
echo -e "  Folder   : ${CYAN}$INST_DIR${NC}"
echo ""
read -rp "$(echo -e "${YELLOW}Lanjutkan? [Y/n]: ${NC}")" CONFIRM
CONFIRM="${CONFIRM:-Y}"
[[ ! "$CONFIRM" =~ ^[Yy]$ ]] && echo "Dibatalkan." && exit 0

# ── Buat folder instance ─────────────────────────────────────
mkdir -p "$INST_DIR"

# ── Tulis .env ───────────────────────────────────────────────
cat > "$INST_DIR/.env" <<EOF
# GenieACS instance: ${USERNAME}
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
GENIEACS_MONGODB_CONNECTION_URL=mongodb://127.0.0.1:27017/${DB_NAME}
GENIEACS_CWMP_PORT=${CWMP_PORT}
GENIEACS_NBI_PORT=${NBI_PORT}
GENIEACS_FS_PORT=${FS_PORT}
GENIEACS_UI_PORT=${UI_PORT}
GENIEACS_FS_HOSTNAME=${SERVER_IP}
GENIEACS_UI_JWT_SECRET=${JWT_SECRET}
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
        warn "Install manual: apt install mongodb-database-tools"
        warn "Lalu: mongorestore --db $DB_NAME --drop $CONF_DIR"
    fi
else
    warn "conf-acs tidak ditemukan di $APP_DIR — skip import MongoDB"
fi

# ── Cari node binary ─────────────────────────────────────────
NODE_BIN=$(command -v node 2>/dev/null || echo "/usr/bin/node")
[[ ! -f "$NODE_BIN" ]] && error "node binary tidak ditemukan di $NODE_BIN"

# ── Buat systemd services ────────────────────────────────────
info "Membuat systemd services..."

declare -A SVC_PORTS=(
    [cwmp]=$CWMP_PORT
    [fs]=$FS_PORT
    [nbi]=$NBI_PORT
    [ui]=$UI_PORT
)

for SVC in cwmp fs nbi ui; do
    PORT="${SVC_PORTS[$SVC]}"
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

systemctl daemon-reload
success "4 systemd services dibuat"

# ── Enable & Start services ──────────────────────────────────
info "Menjalankan services..."
ALL_OK=true

for SVC in cwmp fs nbi ui; do
    systemctl enable "genieacs-${USERNAME}-${SVC}" &>/dev/null 2>&1 || true
    if systemctl start "genieacs-${USERNAME}-${SVC}" 2>/dev/null; then
        sleep 1
        if systemctl is-active --quiet "genieacs-${USERNAME}-${SVC}" 2>/dev/null; then
            success "genieacs-${USERNAME}-${SVC}  ✓ running"
        else
            warn "genieacs-${USERNAME}-${SVC}  ✗ start tapi langsung berhenti"
            warn "  Cek: journalctl -u genieacs-${USERNAME}-${SVC} -n 20 --no-pager"
            ALL_OK=false
        fi
    else
        warn "genieacs-${USERNAME}-${SVC}  ✗ gagal start"
        warn "  Cek: journalctl -u genieacs-${USERNAME}-${SVC} -n 20 --no-pager"
        ALL_OK=false
    fi
done

# ── Simpan ke registry ───────────────────────────────────────
touch "$REGISTRY"
# Hapus entri lama (kalau ada duplikat)
grep -v "^${USERNAME} " "$REGISTRY" > "${REGISTRY}.tmp" 2>/dev/null \
    && mv "${REGISTRY}.tmp" "$REGISTRY" || rm -f "${REGISTRY}.tmp"
echo "${USERNAME} UI=${UI_PORT} CWMP=${CWMP_PORT} NBI=${NBI_PORT} FS=${FS_PORT} DB=${DB_NAME} IP=${SERVER_IP} DATE=$(date '+%Y-%m-%d')" \
    >> "$REGISTRY"

# ── Ringkasan ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}============================================================${NC}"
if $ALL_OK; then
    echo -e "${GREEN}${BOLD}   Instance '${USERNAME}' BERHASIL dibuat & berjalan!${NC}"
else
    echo -e "${YELLOW}${BOLD}   Instance '${USERNAME}' dibuat (ada service gagal — cek log)${NC}"
fi
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "  UI      : ${CYAN}http://${SERVER_IP}:${UI_PORT}${NC}"
echo -e "  CWMP    : ${SERVER_IP}:${CWMP_PORT}"
echo -e "  NBI API : ${SERVER_IP}:${NBI_PORT}"
echo -e "  FS      : ${SERVER_IP}:${FS_PORT}"
echo -e "  Database: ${DB_NAME}"
echo -e "  Folder  : ${INST_DIR}"
echo ""
echo -e "  ${BOLD}Manage instance:${NC}"
echo -e "  ${YELLOW}systemctl status  genieacs-${USERNAME}-ui${NC}"
echo -e "  ${YELLOW}journalctl -u genieacs-${USERNAME}-ui -f${NC}"
echo -e "  ${YELLOW}sudo bash remove-instance.sh ${USERNAME}${NC}"
echo "============================================================"
