#!/bin/bash
# ============================================================
# RadFast ACS — Enable Multi-Proxy Mode
# Gabungkan semua instance proxy ke 1 proses Node.js (hemat RAM)
# ============================================================
set -euo pipefail

# ── Warna ────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[i]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Cek root ─────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "Harus dijalankan sebagai root (pakai sudo)."
    exit 1
fi

REPO_DIR="${RADFAST_REPO_DIR:-/opt/radfast_acs}"
INSTANCES_DIR="${RADFAST_INSTANCES_DIR:-/opt/genieacs-instances}"
REGISTRY="${RADFAST_REGISTRY:-$INSTANCES_DIR/.registry}"
MULTI_SCRIPT="$REPO_DIR/multi-proxy.js"
SERVICE_FILE="/etc/systemd/system/genieacs-multi-proxy.service"

NODE_BIN="$(command -v node || true)"
[[ -z "$NODE_BIN" ]] && { err "Node.js tidak ditemukan."; exit 1; }

[[ -f "$MULTI_SCRIPT" ]] || { err "multi-proxy.js tidak ditemukan di $MULTI_SCRIPT"; exit 1; }
[[ -f "$REGISTRY" ]]     || { err "Registry tidak ditemukan: $REGISTRY (belum ada instance?)"; exit 1; }

echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}   Enable Multi-Proxy Mode${NC}"
echo -e "${GREEN}${BOLD}============================================================${NC}"

# ── Stop & disable semua proxy per-instance ──────────────────
info "Menonaktifkan proxy per-instance..."
STOPPED=0
while read -r LINE; do
    [[ -z "$LINE" ]] && continue
    USER="$(awk '{print $1}' <<< "$LINE")"
    [[ -z "$USER" ]] && continue
    SVC="genieacs-${USER}-proxy"
    if systemctl stop "$SVC" 2>/dev/null; then
        systemctl disable "$SVC" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SVC}.service"
        success "Stop & disable $SVC"
        STOPPED=$((STOPPED + 1))
    fi
done < "$REGISTRY"

# Bersihkan orphan unit proxy per-instance yang tidak ada di registry
for UNIT_FILE in /etc/systemd/system/genieacs-*-proxy.service; do
    [[ -e "$UNIT_FILE" ]] || continue
    UNIT_NAME="$(basename "$UNIT_FILE" .service)"
    [[ "$UNIT_NAME" == "genieacs-multi-proxy" ]] && continue
    systemctl stop "$UNIT_NAME" 2>/dev/null || true
    systemctl disable "$UNIT_NAME" 2>/dev/null || true
    rm -f "$UNIT_FILE"
    success "Hapus orphan $UNIT_NAME"
    STOPPED=$((STOPPED + 1))
done

systemctl daemon-reload
[[ $STOPPED -eq 0 ]] && info "Tidak ada proxy per-instance yang aktif."

# ── Batasi worker GenieACS per service agar RAM/CPU tidak bengkak ───────
# Default GenieACS: 0 = max(2, jumlah CPU) worker PER service.
# Untuk multi-instance kecil/menengah, 1 worker/service jauh lebih hemat.
set_env_value() {
    local file="$1" key="$2" value="$3"
    if grep -qE "^${key}=" "$file" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

info "Mengunci worker GenieACS ke 1 per service untuk semua instance..."
PATCHED=0
while read -r LINE; do
    [[ -z "$LINE" ]] && continue
    USER="$(awk '{print $1}' <<< "$LINE")"
    [[ -z "$USER" ]] && continue
    ENV_FILE="$INSTANCES_DIR/$USER/.env"
    [[ -f "$ENV_FILE" ]] || { warn "Skip $USER: .env tidak ditemukan"; continue; }

    set_env_value "$ENV_FILE" "GENIEACS_CWMP_WORKER_PROCESSES" "1"
    set_env_value "$ENV_FILE" "GENIEACS_NBI_WORKER_PROCESSES" "1"
    set_env_value "$ENV_FILE" "GENIEACS_FS_WORKER_PROCESSES" "1"
    set_env_value "$ENV_FILE" "GENIEACS_UI_WORKER_PROCESSES" "1"
    set_env_value "$ENV_FILE" "NODE_OPTIONS" '"--max-old-space-size=120 --max-semi-space-size=2"'
    success "$USER worker=1 + node heap cap"
    PATCHED=$((PATCHED + 1))
done < "$REGISTRY"

if [[ $PATCHED -gt 0 ]]; then
    info "Memasang MemoryMax=160M untuk core services..."
    while read -r LINE; do
        [[ -z "$LINE" ]] && continue
        USER="$(awk '{print $1}' <<< "$LINE")"
        [[ -z "$USER" ]] && continue
        for SVC in cwmp fs nbi ui; do
            DROPIN_DIR="/etc/systemd/system/genieacs-${USER}-${SVC}.service.d"
            mkdir -p "$DROPIN_DIR"
            cat > "$DROPIN_DIR/limits.conf" <<EOF
[Service]
MemoryAccounting=true
MemoryMax=160M
EOF
        done
    done < "$REGISTRY"

    systemctl daemon-reload
    info "Restart core services agar worker/heap/memory limit aktif..."
    while read -r LINE; do
        [[ -z "$LINE" ]] && continue
        USER="$(awk '{print $1}' <<< "$LINE")"
        [[ -z "$USER" ]] && continue
        for SVC in cwmp fs nbi ui; do
            systemctl restart "genieacs-${USER}-${SVC}" 2>/dev/null || warn "Gagal restart genieacs-${USER}-${SVC}"
        done
    done < "$REGISTRY"
fi

# ── Install service systemd multi-proxy ──────────────────────
info "Membuat service genieacs-multi-proxy..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=RadFast ACS Multi-Instance Logo Proxy
After=network.target

[Service]
Type=simple
Environment=NODE_ENV=production
Environment=NODE_OPTIONS=--max-old-space-size=192 --max-semi-space-size=4
Environment=RADFAST_INSTANCES_DIR=${INSTANCES_DIR}
Environment=RADFAST_REGISTRY=${REGISTRY}
Environment=RADFAST_PROXY_SCRIPT=${REPO_DIR}/logo-proxy.js
ExecStart=${NODE_BIN} ${MULTI_SCRIPT}
Restart=on-failure
RestartSec=5
MemoryAccounting=true
MemoryMax=256M
StandardOutput=journal
StandardError=journal
SyslogIdentifier=genieacs-multi-proxy
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
success "Service file: $SERVICE_FILE"

systemctl daemon-reload
systemctl enable genieacs-multi-proxy &>/dev/null || true

if systemctl restart genieacs-multi-proxy 2>/dev/null; then
    sleep 1
    if systemctl is-active --quiet genieacs-multi-proxy; then
        success "genieacs-multi-proxy berjalan ✓"
    else
        err "genieacs-multi-proxy gagal start — cek: journalctl -u genieacs-multi-proxy -n 50"
        exit 1
    fi
else
    err "Gagal start genieacs-multi-proxy"
    exit 1
fi

echo ""
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}   Multi-Proxy Mode AKTIF!${NC}"
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "  Semua instance proxy sekarang dalam ${CYAN}1 proses Node.js${NC}"
echo ""
echo -e "  ${BOLD}Manage:${NC}"
echo -e "  ${YELLOW}systemctl status genieacs-multi-proxy${NC}"
echo -e "  ${YELLOW}journalctl -u genieacs-multi-proxy -f${NC}"
echo ""
echo -e "  Instance baru via ${CYAN}radfast-add${NC} otomatis ikut mode ini."
echo "============================================================"
