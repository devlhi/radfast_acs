#!/bin/bash
# ============================================================
#  RadFast ACS — One-Line Installer
#  By RadFast Bill
#
#  Usage:
#  curl -fsSL https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh | sudo bash
#  wget -qO-  https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh | sudo bash
# ============================================================

# ── Fix pipe mode ─────────────────────────────────────────────
# Ketika dijalankan via "curl | bash" atau "wget | bash":
# bash membaca SCRIPT dari stdin (pipe). Kalau kita pakai
# "exec < /dev/tty" di sini, bash ganti sumber baca dari pipe
# ke terminal → sisa script hilang → hang blank.
#
# Solusi: download script ke file temp, lalu exec dari file
# dengan stdin diarahkan ke /dev/tty (terminal).
# ─────────────────────────────────────────────────────────────
SELF_URL="https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh"

if [ ! -t 0 ]; then
    TMPSCRIPT=$(mktemp /tmp/radfast_XXXXXX.sh)
    printf '\033[0;36m[RadFast]\033[0m Download installer...\n'
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$SELF_URL" -o "$TMPSCRIPT" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$TMPSCRIPT" "$SELF_URL" 2>/dev/null
    else
        printf '\033[0;31m[ERR]\033[0m curl/wget tidak tersedia!\n'; exit 1
    fi
    chmod +x "$TMPSCRIPT"
    # Jalankan dari FILE (bukan pipe) + stdin dari terminal
    exec bash "$TMPSCRIPT" < /dev/tty
fi

# ── Script berjalan normal (dari file / terminal) ─────────────
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'; DIM='\033[2m'

REPO_URL="https://github.com/devlhi/radfast_acs.git"
REPO_DIR="/opt/radfast_acs"
PROG_TOTAL=5

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR ]${NC} $*"; exit 1; }

# ── Progress bar ──────────────────────────────────────────────
show_progress() {
    local step=$1 total=$2 label="$3"
    local pct=$(( step * 100 / total ))
    local filled=$(( step * 30 / total ))
    local empty=$(( 30 - filled ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty;  i++)); do bar+="░"; done
    printf "  ${CYAN}[%s]${NC} ${BOLD}%3d%%${NC}  %s\n" "$bar" "$pct" "$label"
}

# ── Spinner untuk proses silent ───────────────────────────────
SPINNER_PID=""
spinner_start() {
    local msg="$1"
    ( sp='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'; i=0
      while true; do
          printf "\r  ${CYAN}%s${NC}  %s " "${sp:i++%${#sp}:1}" "$msg"
          sleep 0.1
      done ) &
    SPINNER_PID=$!
    disown "$SPINNER_PID" 2>/dev/null || true
}
spinner_stop() {
    [[ -n "${SPINNER_PID:-}" ]] && kill "$SPINNER_PID" 2>/dev/null || true
    wait "$SPINNER_PID" 2>/dev/null || true
    SPINNER_PID=""
    printf "\r%-70s\r" " "
}

# ── Banner ────────────────────────────────────────────────────
clear
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}RadFast ACS — Installer${NC}                                  ${BOLD}${CYAN}║${NC}"
echo -e "${BOLD}${CYAN}║${NC}  GenieACS v1.2.16 • Multi-Instance • By RadFast Bill      ${BOLD}${CYAN}║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash"

# ── Step 1: Deteksi OS ────────────────────────────────────────
show_progress 1 $PROG_TOTAL "Deteksi OS..."
[[ -f /etc/os-release ]] && . /etc/os-release || true
OS_ID="${ID:-unknown}"; OS_VER="${VERSION_ID:-?}"

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    PKG="apt-get"
elif [[ -f /etc/redhat-release ]]; then
    PKG="yum"; OS_ID="rhel"
else
    error "OS tidak didukung. Butuh Ubuntu 20/22/24 atau RHEL/CentOS."
fi
success "OS: ${OS_ID^} $OS_VER"

# ── Step 2: Update & install dependensi ───────────────────────
show_progress 2 $PROG_TOTAL "Update paket & install dependensi..."

if [[ "$PKG" == "apt-get" ]]; then
    spinner_start "apt-get update..."
    apt-get update -qq 2>/dev/null || true
    spinner_stop
fi

NEED=""
command -v git  &>/dev/null || NEED="$NEED git"
command -v curl &>/dev/null || NEED="$NEED curl"

if [[ -n "$NEED" ]]; then
    spinner_start "Menginstall:$NEED ..."
    [[ "$PKG" == "apt-get" ]] && apt-get install -y -qq $NEED || yum install -y -q $NEED
    spinner_stop
    success "Terinstall:$NEED"
else
    success "git & curl sudah tersedia"
fi

# ── Step 3: Clone / Update repo ───────────────────────────────
show_progress 3 $PROG_TOTAL "Download RadFast ACS dari GitHub..."

if [[ -d "$REPO_DIR/.git" ]]; then
    spinner_start "Update repo..."
    git -C "$REPO_DIR" pull --ff-only 2>&1 | tail -1
    spinner_stop
    success "Repo diupdate"
else
    info "Clone repo ke $REPO_DIR ..."
    git clone --progress "$REPO_URL" "$REPO_DIR" 2>&1 | \
        grep -E "Counting|Receiving|Resolving|done\." || true
    success "Repo di-clone"
fi
chmod +x "$REPO_DIR/"*.sh 2>/dev/null || true

# ── Step 4: Setup sistem ──────────────────────────────────────
show_progress 4 $PROG_TOTAL "Setup sistem (Node.js + MongoDB + GenieACS)..."
echo -e "  ${DIM}──────────────────────────────────────────────────────${NC}"
bash "$REPO_DIR/setup-system.sh"
echo -e "  ${DIM}──────────────────────────────────────────────────────${NC}"

# ── Step 5: Selesai ───────────────────────────────────────────
show_progress 5 $PROG_TOTAL "Instalasi selesai!"
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║  ✅  RadFast ACS berhasil diinstall!                     ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Script dir  : ${CYAN}$REPO_DIR${NC}"
echo -e "  Shortcut    : ${CYAN}radfast-status${NC}  ${CYAN}radfast-list${NC}  ${CYAN}radfast-add${NC}"
echo ""

# ── Tambah instance sekarang? ─────────────────────────────────
read -rp "$(echo -e "${YELLOW}  Tambah instance/user sekarang? [Y/n]: ${NC}")" ADD_NOW
ADD_NOW="${ADD_NOW:-Y}"

if [[ "$ADD_NOW" =~ ^[Yy]$ ]]; then
    echo ""
    bash "$REPO_DIR/add-instance.sh"
else
    echo ""
    echo -e "  Tambah user nanti:"
    echo -e "  ${CYAN}sudo radfast-add${NC}"
    echo -e "  ${CYAN}radfast-list${NC}     ← lihat semua instance"
    echo -e "  ${CYAN}radfast-status${NC}   ← monitor resource"
    echo ""
fi
