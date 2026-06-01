#!/bin/bash
# ============================================================
#  GenieACS Multi-Instance — Retrofit ENV instance lama
#  By RadFast Bill
#
#  Menambahkan setelan baru ke instance yang SUDAH ada:
#    1. RADFAST_NBI_PROXY_PORT  → port publik khusus REST API
#       (auto-pilih port bebas mulai 3500). Tanpa ini, URL API
#       jatuh ke port dashboard.
#    2. ENV VPN status (opsional, kalau --admin-url & --admin-key diisi):
#         RADFAST_ADMIN_URL, RADFAST_ADMIN_API_KEY, RADFAST_INSTANCE_NAME
#       Tanpa ini, modal "Status VPN" menampilkan
#       "belum dikonfigurasi di server".
#
#  Usage:
#    sudo bash retrofit-instances.sh                       # semua instance, NBI proxy port saja
#    sudo bash retrofit-instances.sh kombee                # 1 instance saja
#    sudo bash retrofit-instances.sh --dry-run             # cek saja, tidak mengubah
#    sudo bash retrofit-instances.sh \
#         --admin-url https://panel.example.com \
#         --admin-key RAHASIA_API_KEY                      # sekalian set ENV VPN
#    sudo bash retrofit-instances.sh kombee \
#         --admin-url https://panel.example.com \
#         --admin-key RAHASIA_API_KEY
#
#  Catatan: --admin-key TIDAK ditampilkan ke layar.
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash retrofit-instances.sh"

INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"

[[ ! -d "$INSTANCES_DIR" ]] && error "Folder instances tidak ada: $INSTANCES_DIR"

# ── Argumen ──────────────────────────────────────────────────
DRY_RUN=false
ONLY_INSTANCE=""
ADMIN_URL=""
ADMIN_KEY=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   DRY_RUN=true; shift ;;
        --admin-url) ADMIN_URL="${2:-}"; shift 2 ;;
        --admin-key) ADMIN_KEY="${2:-}"; shift 2 ;;
        -*)          error "Opsi tidak dikenal: $1" ;;
        *)           ONLY_INSTANCE="$1"; shift ;;
    esac
done

$DRY_RUN && warn "MODE DRY-RUN: hanya menampilkan rencana, tidak mengubah apa pun."

SET_VPN=false
if [[ -n "$ADMIN_URL" || -n "$ADMIN_KEY" ]]; then
    [[ -z "$ADMIN_URL" ]] && error "--admin-url wajib diisi bila --admin-key diberikan."
    [[ -z "$ADMIN_KEY" ]] && error "--admin-key wajib diisi bila --admin-url diberikan."
    # Buang trailing slash agar runtime tinggal append path.
    ADMIN_URL="${ADMIN_URL%/}"
    SET_VPN=true
    info "ENV VPN akan di-set (URL: ${ADMIN_URL}, key: tersembunyi)."
else
    info "ENV VPN dilewati (jalankan dengan --admin-url & --admin-key untuk set)."
fi

# ── Kumpulkan SEMUA port yang sedang dipakai ────────────────
collect_used_ports() {
    {
        grep -rh "_PORT=" "$INSTANCES_DIR/"*"/.env" 2>/dev/null \
            | grep -oP '=\K[0-9]+$' || true
        ss -tlnp 2>/dev/null | grep -oP '(?<=:)\d+(?= )' || \
        netstat -tlnp 2>/dev/null | grep -oP ':\K[0-9]+(?= )' || true
    } | sort -un
}

USED_PORTS=$(collect_used_ports)
is_used() { echo "$USED_PORTS" | grep -qx "$1"; }

# Cari port bebas mulai dari $1, lalu reservasi ke USED_PORTS.
# TIDAK pakai command substitution agar update USED_PORTS tidak hilang.
reserve_port() {
    local p=$1
    while is_used "$p"; do p=$((p + 1)); done
    USED_PORTS=$(printf "%s\n%s" "$USED_PORTS" "$p" | sort -un)
    RESERVED_PORT="$p"
}

# ── Baca / set nilai di .env ────────────────────────────────
# CATATAN: tambahkan `|| true` di akhir pipeline. Tanpa ini, saat key belum
# ada, grep exit 1 → `set -o pipefail` bikin command substitution gagal →
# `set -e` menghentikan script diam-diam (gejala: berhenti di "Instance xxx").
get_env() {
    local file="$1" key="$2"
    grep -E "^${key}=" "$file" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '[:space:]' || true
}

# Set/replace value di .env (in-place, aman untuk karakter URL).
set_env() {
    local file="$1" key="$2" val="$3"
    if grep -qE "^${key}=" "$file"; then
        # Pakai pemisah '|' agar slash di URL tidak mengganggu sed.
        local esc
        esc=$(printf '%s' "$val" | sed -e 's/[\\&|]/\\&/g')
        sed -i "s|^${key}=.*|${key}=${esc}|" "$file"
    else
        printf '%s=%s\n' "$key" "$val" >> "$file"
    fi
}

# ── Daftar instance yang akan diproses ──────────────────────
if [[ -n "$ONLY_INSTANCE" ]]; then
    [[ -d "$INSTANCES_DIR/$ONLY_INSTANCE" ]] || error "Instance tidak ada: $ONLY_INSTANCE"
    INSTANCE_LIST="$ONLY_INSTANCE"
else
    INSTANCE_LIST=$(find "$INSTANCES_DIR" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | sort)
fi

[[ -z "$INSTANCE_LIST" ]] && error "Tidak ada instance ditemukan di $INSTANCES_DIR"

CHANGED_ANY=false

# ── Proses tiap instance ────────────────────────────────────
for NAME in $INSTANCE_LIST; do
    ENV_FILE="$INSTANCES_DIR/$NAME/.env"
    [[ -f "$ENV_FILE" ]] || { warn "skip $NAME: .env tidak ada"; continue; }

    echo ""
    info "Instance ${BOLD}${NAME}${NC}"

    CHANGED=false
    PLAN=""

    # 1) NBI proxy port — tambahkan hanya jika belum ada / kosong.
    CUR_NBIP=$(get_env "$ENV_FILE" RADFAST_NBI_PROXY_PORT)
    if [[ -z "$CUR_NBIP" || "$CUR_NBIP" == "0" ]]; then
        reserve_port 3500; NEW_NBIP="$RESERVED_PORT"
        PLAN+="  + RADFAST_NBI_PROXY_PORT=${NEW_NBIP}\n"
        CHANGED=true
    else
        success "  RADFAST_NBI_PROXY_PORT sudah ada: ${CUR_NBIP} (dilewati)"
        NEW_NBIP=""
    fi

    # 2) ENV VPN (opsional).
    if $SET_VPN; then
        PLAN+="  + RADFAST_ADMIN_URL=${ADMIN_URL}\n"
        PLAN+="  + RADFAST_ADMIN_API_KEY=******** (tersembunyi)\n"
        PLAN+="  + RADFAST_INSTANCE_NAME=${NAME}\n"
        CHANGED=true
    fi

    if ! $CHANGED; then
        success "  Tidak ada yang perlu diubah."
        continue
    fi

    echo -e "$PLAN"

    if $DRY_RUN; then
        info "  [dry-run] perubahan di atas TIDAK ditulis."
        CHANGED_ANY=true
        continue
    fi

    # Backup .env sebelum diubah
    cp -a "$ENV_FILE" "${ENV_FILE}.bak.$(date '+%Y%m%d%H%M%S')"

    [[ -n "$NEW_NBIP" ]] && set_env "$ENV_FILE" RADFAST_NBI_PROXY_PORT "$NEW_NBIP"
    if $SET_VPN; then
        set_env "$ENV_FILE" RADFAST_ADMIN_URL      "$ADMIN_URL"
        set_env "$ENV_FILE" RADFAST_ADMIN_API_KEY  "$ADMIN_KEY"
        set_env "$ENV_FILE" RADFAST_INSTANCE_NAME  "$NAME"
    fi
    success "  .env diupdate (backup dibuat)."
    CHANGED_ANY=true
done

# ── Restart multi-proxy sekali di akhir ─────────────────────
if $CHANGED_ANY && ! $DRY_RUN; then
    echo ""
    info "Restart genieacs-multi-proxy agar setelan baru terbaca..."
    if systemctl restart genieacs-multi-proxy 2>/dev/null; then
        success "genieacs-multi-proxy ✓"
    else
        warn "Gagal restart genieacs-multi-proxy (cek: journalctl -u genieacs-multi-proxy -n 20)"
    fi
fi

echo ""
if $DRY_RUN; then
    success "Selesai (dry-run). Jalankan tanpa --dry-run untuk menerapkan."
elif $CHANGED_ANY; then
    success "Selesai. Instance sudah di-retrofit."
    echo ""
    info "Verifikasi cepat:"
    echo "  grep -H -E 'RADFAST_(NBI_PROXY_PORT|ADMIN_URL|ADMIN_API_KEY|INSTANCE_NAME)' $INSTANCES_DIR/*/.env"
    echo "  sudo ss -ltnp | grep node"
    echo ""
    info "Lalu buka dashboard instance → tombol 'API URL' (port REST API baru) & 'Status VPN'."
else
    success "Selesai. Tidak ada perubahan diperlukan."
fi
