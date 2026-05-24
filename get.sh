#!/bin/bash
# ============================================================
#  RadFast ACS — Bootstrap Installer
#  By RadFast Bill
# ============================================================
#
#  CARA INSTALL (copy salah satu):
#
#  wget -O /tmp/r.sh https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh && bash /tmp/r.sh
#  curl -fsSL     https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh -o /tmp/r.sh && bash /tmp/r.sh
#
# ============================================================

# ── Jika masih dijalankan via pipe lama (curl|bash / wget|bash)
#    bootstrap ini minimal — langsung download ke file lalu exec
# ─────────────────────────────────────────────────────────────
_MAIN() {

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

show_progress() {
    local step=$1 total=$2 label="$3"
    local pct=$(( step * 100 / total ))
    local filled=$(( step * 30 / total ))
    local empty=$(( 30 - filled ))
    local bar="" i
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty;  i++)); do bar+="░"; done
    printf "  ${CYAN}[%s]${NC} ${BOLD}%3d%%${NC}  %s\n" "$bar" "$pct" "$label"
}

SPINNER_PID=""
spinner_start() {
    ( sp='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'; i=0
      while true; do
          printf "\r  ${CYAN}%s${NC}  %s " "${sp:i++%${#sp}:1}" "$1"
          sleep 0.1
      done ) &
    SPINNER_PID=$!
    disown "$SPINNER_PID" 2>/dev/null || true
}
spinner_stop() {
    [[ -n "${SPINNER_PID:-}" ]] && kill "$SPINNER_PID" 2>/dev/null; wait "$SPINNER_PID" 2>/dev/null || true
    SPINNER_PID=""; printf "\r%-70s\r" " "
}

# ── Banner ────────────────────────────────────────────────────
clear
echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}RadFast ACS — Installer${NC}                                  ${BOLD}${CYAN}║${NC}"
echo -e "${BOLD}${CYAN}║${NC}  GenieACS v1.2.16 • Multi-Instance • By RadFast Bill      ${BOLD}${CYAN}║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash /tmp/r.sh"

# ── Step 1: Deteksi OS ────────────────────────────────────────
show_progress 1 $PROG_TOTAL "Deteksi OS..."
[[ -f /etc/os-release ]] && . /etc/os-release || true
OS_ID="${ID:-unknown}"; OS_VER="${VERSION_ID:-?}"

if   [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then PKG="apt-get"
elif [[ -f /etc/redhat-release ]]; then PKG="yum"; OS_ID="rhel"
else error "OS tidak didukung. Butuh Ubuntu 20/22/24 atau RHEL/CentOS."
fi
success "OS: ${OS_ID^} $OS_VER"

# ── Step 2: Update & dependensi ───────────────────────────────
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
    spinner_start "Install:$NEED ..."
    [[ "$PKG" == "apt-get" ]] && apt-get install -y -qq $NEED || yum install -y -q $NEED
    spinner_stop; success "Terinstall:$NEED"
else
    success "git & curl sudah tersedia"
fi

# ── Step 3: Clone / Update repo ───────────────────────────────
show_progress 3 $PROG_TOTAL "Download RadFast ACS dari GitHub..."
if [[ -d "$REPO_DIR/.git" ]]; then
    spinner_start "Update repo..."
    git -C "$REPO_DIR" pull --ff-only 2>&1 | tail -1
    spinner_stop; success "Repo diupdate"
else
    info "Clone repo ke $REPO_DIR ..."
    git clone --progress "$REPO_URL" "$REPO_DIR" 2>&1 | grep -E "Counting|Receiving|Resolving|done\." || true
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
echo -e "  Shortcut : ${CYAN}radfast-status${NC}  ${CYAN}radfast-list${NC}  ${CYAN}radfast-add${NC}"
echo ""

read -rp "$(echo -e "${YELLOW}  Tambah instance/user sekarang? [Y/n]: ${NC}")" ADD_NOW
ADD_NOW="${ADD_NOW:-Y}"
if [[ "$ADD_NOW" =~ ^[Yy]$ ]]; then
    echo ""; bash "$REPO_DIR/add-instance.sh"
else
    echo ""
    echo -e "  Tambah nanti: ${CYAN}sudo radfast-add${NC}"
    echo -e "  List       : ${CYAN}radfast-list${NC}"
    echo ""
fi

} # end _MAIN

# ══════════════════════════════════════════════════════════════
#  ENTRYPOINT
#  Cara jalankan yang direkomendasikan:
#
#  wget -O /tmp/r.sh URL && sudo bash /tmp/r.sh   ← paling kompatibel
#  curl URL -o /tmp/r.sh && sudo bash /tmp/r.sh   ← alternatif curl
#
#  TIDAK direkomendasikan:
#  bash <(curl ...) → tidak jalan di LXC (tidak ada /dev/fd)
#  curl | bash      → stdin bukan tty → prompt interaktif tidak tampil
#                     (script handle otomatis via download ke tmpfile)
#
#  Deteksi:
#  - bash file.sh  → stdin IS tty  → _MAIN langsung
#  - curl | bash   → stdin bukan tty → download ke tmpfile dulu
# ══════════════════════════════════════════════════════════════
if [ ! -t 0 ]; then
    # Dijalankan via pipe langsung (curl|bash / wget|bash)
    # stdin bukan terminal → interactive read tidak bisa
    # Solusi: download ke file sementara lalu exec
    SELF="https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh"
    TMP=$(mktemp /tmp/radfast_XXXXXX.sh)
    printf '\033[1;33m[RadFast]\033[0m Mendownload installer ke %s\n' "$TMP"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --progress-bar "$SELF" -o "$TMP"
    else
        wget --show-progress -qO "$TMP" "$SELF" 2>&1 || wget -O "$TMP" "$SELF"
    fi
    chmod +x "$TMP"
    printf '\033[0;32m[ OK ]\033[0m Download selesai. Menjalankan installer...\n\n'
    exec bash "$TMP" </dev/tty
else
    # bash <(curl ...) atau bash file.sh — stdin terminal, langsung jalan
    _MAIN
fi
