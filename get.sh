#!/bin/bash
# ============================================================
#  RadFast ACS — One-Line Installer
#  By RadFast Bill
#
#  Usage:
#  wget -qO- https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh | bash
#  curl -fsSL https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh | bash
# ============================================================

# ── Jika dijalankan via pipe, redirect stdin ke /dev/tty ─────
if [ ! -t 0 ]; then
    if [ -e /dev/tty ]; then
        exec < /dev/tty
    else
        # /dev/tty tidak tersedia — download dulu lalu exec langsung
        SELF_URL="https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh"
        echo "[INFO] Mendeteksi pipe tanpa TTY, download ke /tmp dulu..."
        curl -fsSL "$SELF_URL" -o /tmp/radfast_get.sh 2>/dev/null || \
            wget -qO  /tmp/radfast_get.sh "$SELF_URL" 2>/dev/null
        exec bash /tmp/radfast_get.sh
    fi
fi

set -euo pipefail

# ── Warna ─────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'; DIM='\033[2m'

REPO_URL="https://github.com/devlhi/radfast_acs.git"
REPO_DIR="/opt/radfast_acs"

# ── Helper functions ──────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR ]${NC} $*"; exit 1; }

# Progress bar: progress <step> <total> <label>
PROG_TOTAL=6
PROG_STEP=0
show_progress() {
    local step=$1
    local total=$2
    local label="$3"
    local pct=$(( step * 100 / total ))
    local filled=$(( step * 30 / total ))
    local empty=$(( 30 - filled ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty;  i++)); do bar+="░"; done
    printf "\r  ${CYAN}[${bar}]${NC} ${BOLD}%3d%%${NC}  %s" "$pct" "$label"
    [[ $step -eq $total ]] && echo ""
}

# Spinner untuk proses yang tidak ada output (silent)
spinner_start() {
    local msg="$1"
    SPINNER_MSG="$msg"
    SPINNER_PID=""
    (
        sp='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        i=0
        while true; do
            printf "\r  ${CYAN}%s${NC}  %s " "${sp:i++%${#sp}:1}" "$SPINNER_MSG"
            sleep 0.1
        done
    ) &
    SPINNER_PID=$!
    disown "$SPINNER_PID" 2>/dev/null || true
}

spinner_stop() {
    if [[ -n "${SPINNER_PID:-}" ]]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
        printf "\r%-60s\r" " "   # bersihkan baris spinner
    fi
}

# ── Banner ────────────────────────────────────────────────────
clear
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}RadFast ACS — Installer${NC}                                  ${BOLD}${CYAN}║${NC}"
echo -e "${BOLD}${CYAN}║${NC}  GenieACS v1.2.16 • Multi-Instance • By RadFast Bill      ${BOLD}${CYAN}║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Cek root ──────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash"

# ── STEP 1: Deteksi OS ────────────────────────────────────────
PROG_STEP=1
show_progress $PROG_STEP $PROG_TOTAL "Deteksi OS..."

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VER="${VERSION_ID:-?}"
else
    OS_ID="unknown"; OS_VER="?"
fi

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    PKG="apt-get"
elif [[ -f /etc/redhat-release ]]; then
    PKG="yum"; OS_ID="rhel"
else
    error "OS tidak didukung. Butuh Ubuntu 20/22/24 atau RHEL/CentOS."
fi

success "OS: ${OS_ID^} $OS_VER"

# ── STEP 2: Update apt cache ──────────────────────────────────
PROG_STEP=2
show_progress $PROG_STEP $PROG_TOTAL "Update paket list..."

if [[ "$PKG" == "apt-get" ]]; then
    spinner_start "Menjalankan apt-get update..."
    apt-get update -qq 2>/dev/null || true
    spinner_stop
    success "apt-get update selesai"
fi

# ── STEP 3: Install git & curl ────────────────────────────────
PROG_STEP=3
show_progress $PROG_STEP $PROG_TOTAL "Cek dependensi (git, curl)..."

NEED_INSTALL=""
command -v git  &>/dev/null || NEED_INSTALL="$NEED_INSTALL git"
command -v curl &>/dev/null || NEED_INSTALL="$NEED_INSTALL curl"

if [[ -n "$NEED_INSTALL" ]]; then
    spinner_start "Menginstall:$NEED_INSTALL ..."
    if [[ "$PKG" == "apt-get" ]]; then
        apt-get install -y $NEED_INSTALL -qq 2>/dev/null
    else
        yum install -y $NEED_INSTALL -q 2>/dev/null
    fi
    spinner_stop
    success "Terinstall:$NEED_INSTALL"
else
    success "git & curl sudah tersedia"
fi

# ── STEP 4: Clone / Update repo ───────────────────────────────
PROG_STEP=4
show_progress $PROG_STEP $PROG_TOTAL "Download RadFast ACS dari GitHub..."

if [[ -d "$REPO_DIR/.git" ]]; then
    spinner_start "Update repo $REPO_DIR ..."
    git -C "$REPO_DIR" pull --ff-only 2>&1 | tail -2
    spinner_stop
    success "Repo diupdate ke versi terbaru"
else
    echo ""
    info "Clone repo ke $REPO_DIR ..."
    # git clone dengan progress (tampil di terminal)
    git clone --progress "$REPO_URL" "$REPO_DIR" 2>&1 | \
        grep -E "Counting|Compressing|Receiving|Resolving|done\." || true
    success "Repo berhasil di-clone"
fi

chmod +x "$REPO_DIR/"*.sh 2>/dev/null || true
cd "$REPO_DIR"

# ── STEP 5: Setup sistem ──────────────────────────────────────
PROG_STEP=5
show_progress $PROG_STEP $PROG_TOTAL "Setup sistem (Node.js, MongoDB, GenieACS)..."
echo ""
echo -e "  ${DIM}─────────────────────────────────────────────────${NC}"

bash "$REPO_DIR/setup-system.sh"

echo -e "  ${DIM}─────────────────────────────────────────────────${NC}"

# ── STEP 6: Selesai ───────────────────────────────────────────
PROG_STEP=6
show_progress $PROG_STEP $PROG_TOTAL "Instalasi selesai!"
echo ""

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  ✅  RadFast ACS berhasil diinstall!                     ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Script tersedia di : ${CYAN}$REPO_DIR${NC}"
echo -e "  Shortcut command   : ${CYAN}radfast-status / radfast-list / radfast-add${NC}"
echo ""

# ── Tanya tambah instance sekarang ───────────────────────────
read -rp "$(echo -e "${YELLOW}  Tambah instance/user sekarang? [Y/n]: ${NC}")" ADD_NOW
ADD_NOW="${ADD_NOW:-Y}"

if [[ "$ADD_NOW" =~ ^[Yy]$ ]]; then
    echo ""
    bash "$REPO_DIR/add-instance.sh"
else
    echo ""
    echo -e "  Tambah user nanti dengan:"
    echo -e "  ${CYAN}sudo radfast-add${NC}"
    echo -e "  ${CYAN}radfast-list${NC}    ← lihat semua instance"
    echo -e "  ${CYAN}radfast-status${NC}  ← monitor resource"
    echo ""
fi
