#!/bin/bash
# ============================================================
#  GenieACS Multi-Instance — Perbaiki Port Duplikat
#  By RadFast Bill
#
#  Memindai semua instance, mendeteksi port yang tabrakan
#  (CWMP/NBI/FS/UI sama, atau bentrok antar-instance), lalu
#  meng-assign ulang port yang bentrok ke port acak yang bebas.
#  Setelah itu .env + .registry diupdate dan service di-restart.
#
#  Usage:
#    sudo bash fix-duplicate-ports.sh            # perbaiki semua instance
#    sudo bash fix-duplicate-ports.sh kombee     # perbaiki 1 instance saja
#    sudo bash fix-duplicate-ports.sh --dry-run  # cek saja, tidak mengubah
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash fix-duplicate-ports.sh"

INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"

[[ ! -d "$INSTANCES_DIR" ]] && error "Folder instances tidak ada: $INSTANCES_DIR"

# ── Argumen ──────────────────────────────────────────────────
DRY_RUN=false
ONLY_INSTANCE=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        -*)        error "Opsi tidak dikenal: $arg" ;;
        *)         ONLY_INSTANCE="$arg" ;;
    esac
done

$DRY_RUN && warn "MODE DRY-RUN: hanya menampilkan rencana, tidak mengubah apa pun."

# ── Kumpulkan SEMUA port yang sedang dipakai ────────────────
# Sumber: semua .env instance + port yang sedang LISTEN di OS.
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
# Hasil ditaruh di RESERVED_PORT (TIDAK pakai command substitution agar
# update USED_PORTS tidak hilang di subshell).
reserve_port() {
    local p=$1
    while is_used "$p"; do p=$((p + 1)); done
    USED_PORTS=$(printf "%s\n%s" "$USED_PORTS" "$p" | sort -un)
    RESERVED_PORT="$p"
}

# Tandai port sebagai used tanpa mencari (untuk port existing yang valid).
mark_used() { USED_PORTS=$(printf "%s\n%s" "$USED_PORTS" "$1" | sort -un); }

# ── Baca nilai port dari .env ───────────────────────────────
get_env() {
    local file="$1" key="$2"
    grep -E "^${key}=" "$file" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '[:space:]'
}

# ── Ganti nilai port di .env (in-place, aman) ───────────────
set_env_port() {
    local file="$1" key="$2" val="$3"
    if grep -qE "^${key}=" "$file"; then
        sed -i "s/^${key}=.*/${key}=${val}/" "$file"
    else
        echo "${key}=${val}" >> "$file"
    fi
}

# ── Update baris registry untuk instance ────────────────────
update_registry() {
    local name="$1" ui="$2" cwmp="$3" nbi="$4" fs="$5"
    [[ -f "$REGISTRY" ]] || return 0
    local db ip date line
    line=$(grep -E "^${name} " "$REGISTRY" 2>/dev/null | head -n1 || true)
    [[ -z "$line" ]] && return 0
    db=$(echo "$line"   | grep -oP 'DB=\K[^ ]+'   || echo "")
    ip=$(echo "$line"   | grep -oP 'IP=\K[^ ]+'   || echo "")
    date=$(echo "$line" | grep -oP 'DATE=\K[^ ]+' || date '+%Y-%m-%d')
    grep -v "^${name} " "$REGISTRY" > "${REGISTRY}.tmp" 2>/dev/null || true
    echo "${name} UI=${ui} CWMP=${cwmp} NBI=${nbi} FS=${fs} DB=${db} IP=${ip} DATE=${date}" >> "${REGISTRY}.tmp"
    mv "${REGISTRY}.tmp" "$REGISTRY"
}

# ── Tracking port yang sudah dipastikan dipakai run ini ─────
CLAIMED_PORTS=""
is_claimed() { echo "$CLAIMED_PORTS" | grep -qx "$1"; }
claim() {
    CLAIMED_PORTS=$(printf "%s\n%s" "$CLAIMED_PORTS" "$1" | sort -un)
    mark_used "$1"
}

# ── Restart service satu instance ───────────────────────────
restart_instance() {
    local name="$1"; shift
    local svcs="$*"
    for svc in $svcs; do
        local unit="genieacs-${name}-${svc}"
        if systemctl restart "$unit" 2>/dev/null; then
            sleep 1
            if systemctl is-active --quiet "$unit" 2>/dev/null; then
                success "  restart $unit ✓"
            else
                warn "  $unit gagal aktif (cek: journalctl -u $unit -n 20)"
            fi
        else
            warn "  gagal restart $unit"
        fi
    done
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

    CWMP=$(get_env "$ENV_FILE" GENIEACS_CWMP_PORT)
    NBI=$(get_env "$ENV_FILE" GENIEACS_NBI_PORT)
    FS=$(get_env "$ENV_FILE" GENIEACS_FS_PORT)

    OLD_CWMP="$CWMP"; OLD_NBI="$NBI"; OLD_FS="$FS"
    CHANGED=false

    echo ""
    info "Instance ${BOLD}${NAME}${NC} — CWMP=${CWMP:-?} NBI=${NBI:-?} FS=${FS:-?}"

    # CWMP: pertahankan jika valid & belum diklaim instance lain (device
    # connect ke port ini — hindari mengubah bila tidak perlu).
    if [[ -z "$CWMP" ]] || is_claimed "$CWMP"; then
        reserve_port 7548; CWMP="$RESERVED_PORT"; CHANGED=true
        warn "  CWMP bentrok/kosong → dialokasikan ulang: ${OLD_CWMP:-(kosong)} → $CWMP"
    fi
    claim "$CWMP"

    # NBI: wajib beda dari CWMP & tidak diklaim pihak lain.
    if [[ -z "$NBI" ]] || is_claimed "$NBI" || [[ "$NBI" == "$CWMP" ]]; then
        reserve_port 7558; NBI="$RESERVED_PORT"; CHANGED=true
        warn "  NBI bentrok/kosong → dialokasikan ulang: ${OLD_NBI:-(kosong)} → $NBI"
    fi
    claim "$NBI"

    # FS: wajib beda dari CWMP & NBI & tidak diklaim pihak lain.
    if [[ -z "$FS" ]] || is_claimed "$FS" || [[ "$FS" == "$CWMP" ]] || [[ "$FS" == "$NBI" ]]; then
        reserve_port 7568; FS="$RESERVED_PORT"; CHANGED=true
        warn "  FS bentrok/kosong → dialokasikan ulang: ${OLD_FS:-(kosong)} → $FS"
    fi
    claim "$FS"

    if ! $CHANGED; then
        success "  Port sudah unik, tidak ada perubahan."
        continue
    fi

    CHANGED_ANY=true

    if $DRY_RUN; then
        info "  [dry-run] akan set: CWMP=$CWMP NBI=$NBI FS=$FS (tidak ditulis)"
        continue
    fi

    # Backup .env sebelum diubah
    cp -a "$ENV_FILE" "${ENV_FILE}.bak.$(date '+%Y%m%d%H%M%S')"

    set_env_port "$ENV_FILE" GENIEACS_CWMP_PORT "$CWMP"
    set_env_port "$ENV_FILE" GENIEACS_NBI_PORT  "$NBI"
    set_env_port "$ENV_FILE" GENIEACS_FS_PORT   "$FS"
    success "  .env diupdate (backup dibuat)."

    # Update registry (UI port dibaca dari .env / registry lama)
    UI_PUB=$(get_env "$ENV_FILE" RADFAST_PROXY_PORT)
    [[ -z "$UI_PUB" ]] && UI_PUB=$(grep -E "^${NAME} " "$REGISTRY" 2>/dev/null | grep -oP 'UI=\K[0-9]+' || echo "")
    update_registry "$NAME" "${UI_PUB:-0}" "$CWMP" "$NBI" "$FS"
    success "  .registry diupdate."

    # Restart service yang terdampak
    restart_instance "$NAME" cwmp nbi fs
done

# ── Restart multi-proxy sekali di akhir ─────────────────────
if $CHANGED_ANY && ! $DRY_RUN; then
    echo ""
    info "Restart genieacs-multi-proxy agar mapping port baru terbaca..."
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
    success "Selesai. Port duplikat diperbaiki."
    echo ""
    info "Verifikasi cepat:"
    echo "  grep -H -E 'GENIEACS_(CWMP|NBI|FS)_PORT' $INSTANCES_DIR/*/.env"
    echo "  sudo ss -ltnp | grep node"
else
    success "Selesai. Tidak ada port duplikat — semua instance aman."
fi
