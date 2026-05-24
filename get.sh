#!/bin/bash
# ============================================================
#  RadFast ACS — One-Line Installer
#  By RadFast Bill
#
#  Usage:
#  wget -qO- https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh | bash
#  curl -fsSL https://raw.githubusercontent.com/devlhi/radfast_acs/main/get.sh | bash
# ============================================================

# ── Jika dijalankan via pipe (wget|bash / curl|bash),
#    stdin bukan terminal — redirect ke /dev/tty supaya
#    script interaktif (read, konfirmasi) tetap bisa input ──
[ ! -t 0 ] && exec < /dev/tty

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

REPO_URL="https://github.com/devlhi/radfast_acs.git"
REPO_DIR="/opt/radfast_acs"

echo -e "${BOLD}"
echo "============================================================"
echo "   RadFast ACS — Installer"
echo "   GenieACS v1.2.16 Multi-Instance"
echo "   By RadFast Bill"
echo "============================================================"
echo -e "${NC}"

# ── Cek root ─────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Jalankan sebagai root:\n  wget -qO- $REPO_URL/raw/main/get.sh | sudo bash"

# ── Deteksi OS ───────────────────────────────────────────────
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
else
    OS_ID="unknown"
fi

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" ]]; then
    PKG="apt-get"
elif [[ -f /etc/redhat-release ]]; then
    PKG="yum"
    OS_ID="rhel"
else
    error "OS tidak didukung. Butuh Ubuntu 20/22/24 atau RHEL/CentOS."
fi

info "OS: $OS_ID"

# ── Update apt cache (sekali) ────────────────────────────────
if [[ "$PKG" == "apt-get" ]]; then
    info "Update apt cache..."
    apt-get update -qq 2>/dev/null || true
fi

# ── Install git & curl jika belum ada ────────────────────────
NEED_INSTALL=""
command -v git  &>/dev/null || NEED_INSTALL="$NEED_INSTALL git"
command -v curl &>/dev/null || NEED_INSTALL="$NEED_INSTALL curl"

if [[ -n "$NEED_INSTALL" ]]; then
    info "Menginstall:$NEED_INSTALL..."
    if [[ "$PKG" == "apt-get" ]]; then
        apt-get install -y $NEED_INSTALL
    else
        yum install -y $NEED_INSTALL
    fi
fi
success "git & curl tersedia"

# ── Clone / Update repo ──────────────────────────────────────
if [[ -d "$REPO_DIR/.git" ]]; then
    info "Repo sudah ada di $REPO_DIR — update ke versi terbaru..."
    git -C "$REPO_DIR" pull --ff-only 2>&1 | tail -3
    success "Repo diupdate"
else
    info "Clone repo ke $REPO_DIR..."
    git clone "$REPO_URL" "$REPO_DIR"
    success "Repo berhasil di-clone"
fi

chmod +x "$REPO_DIR/"*.sh
cd "$REPO_DIR"

# ── Jalankan setup-system.sh ─────────────────────────────────
echo ""
info "Menjalankan setup sistem..."
bash "$REPO_DIR/setup-system.sh"

# ── Tanya tambah instance sekarang ───────────────────────────
echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "  Setup selesai!"
echo -e "  Script tersedia di: ${CYAN}$REPO_DIR${NC}"
echo -e "============================================================"
echo ""
read -rp "$(echo -e "${YELLOW}Tambah instance/user sekarang? [Y/n]: ${NC}")" ADD_NOW
ADD_NOW="${ADD_NOW:-Y}"

if [[ "$ADD_NOW" =~ ^[Yy]$ ]]; then
    bash "$REPO_DIR/add-instance.sh"
else
    echo ""
    echo -e "  Tambah user nanti:"
    echo -e "  ${CYAN}sudo bash $REPO_DIR/add-instance.sh${NC}"
    echo ""
    echo -e "  Atau bisa pakai alias cepat:"
    echo -e "  ${CYAN}sudo bash /opt/radfast_acs/add-instance.sh${NC}"
    echo -e "  ${CYAN}bash /opt/radfast_acs/list-instances.sh${NC}"
    echo ""
fi
