#!/bin/bash
# ============================================================
#  GenieACS Multi-Instance — System Setup (jalankan SEKALI)
#  Support: Ubuntu 20.04 / 22.04 / 24.04 / RHEL / CentOS
#  Node.js : 18 LTS
#  MongoDB : 7.0
#  By RadFast Bill
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

echo -e "${BOLD}"
echo "============================================================"
echo "   GenieACS Multi-Instance — System Setup"
echo "   By RadFast Bill"
echo "============================================================"
echo -e "${NC}"

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash setup-system.sh"

# ── Deteksi OS & Ubuntu version ──────────────────────────────
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_VER="${VERSION_ID:-unknown}"
    OS_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-unknown}}"
else
    OS_ID="unknown"
    OS_VER="unknown"
    OS_CODENAME="unknown"
fi

if [[ "$OS_ID" == "ubuntu" ]]; then
    OS_TYPE="debian"
    info "OS: Ubuntu $OS_VER ($OS_CODENAME)"

    # Pastikan codename benar
    case "$OS_VER" in
        20.04) OS_CODENAME="focal"  ;;
        22.04) OS_CODENAME="jammy"  ;;
        24.04) OS_CODENAME="noble"  ;;
        *)
            # Coba ambil dari lsb_release
            if command -v lsb_release &>/dev/null; then
                OS_CODENAME=$(lsb_release -cs)
            fi
            warn "Ubuntu $OS_VER — codename: $OS_CODENAME (mungkin belum diuji)"
            ;;
    esac

elif [[ "$OS_ID" == "debian" ]]; then
    OS_TYPE="debian"
    info "OS: Debian $OS_VER ($OS_CODENAME)"

elif [[ -f /etc/redhat-release ]]; then
    OS_TYPE="rhel"
    info "OS: RHEL/CentOS"

else
    error "OS tidak didukung. Butuh Ubuntu 20/22/24 atau RHEL/CentOS."
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DST="/opt/genieacs-app"
INSTANCES_DIR="/opt/genieacs-instances"

# Cari folder genieacs-app (support beberapa struktur folder)
if [[ -d "$SCRIPT_DIR/source-deob/genieacs-app" ]]; then
    APP_SRC="$SCRIPT_DIR/source-deob/genieacs-app"
elif [[ -d "$SCRIPT_DIR/genieacs-app" ]]; then
    APP_SRC="$SCRIPT_DIR/genieacs-app"
else
    error "Folder genieacs-app tidak ditemukan di $SCRIPT_DIR"
fi

# ── Update apt cache ─────────────────────────────────────────
if [[ "$OS_TYPE" == "debian" ]]; then
    info "Update apt cache..."
    apt-get update -qq 2>/dev/null || true
fi

# ── Install curl & gnupg (dibutuhkan semua langkah) ──────────
if [[ "$OS_TYPE" == "debian" ]]; then
    PKGS_NEEDED=""
    command -v curl   &>/dev/null || PKGS_NEEDED="$PKGS_NEEDED curl"
    command -v gpg    &>/dev/null || PKGS_NEEDED="$PKGS_NEEDED gnupg"
    dpkg -l ca-certificates &>/dev/null 2>&1 | grep -q "^ii" || PKGS_NEEDED="$PKGS_NEEDED ca-certificates"
    if [[ -n "$PKGS_NEEDED" ]]; then
        info "Menginstall tools:$PKGS_NEEDED..."
        apt-get install -y $PKGS_NEEDED
    fi
fi

# ════════════════════════════════════════════════════════════
#  INSTALL NODE.JS 18 LTS
# ════════════════════════════════════════════════════════════
info "=== Node.js 18 LTS ==="

install_nodejs_18() {
    if [[ "$OS_TYPE" == "debian" ]]; then

        # Deteksi apakah NodeSource sudah di-setup
        if [[ -f /etc/apt/sources.list.d/nodesource.list ]] || \
           ls /etc/apt/sources.list.d/nodejs* 2>/dev/null | grep -q .; then
            info "NodeSource repo sudah ada, skip setup"
        else
            info "Menambahkan NodeSource repo (Node.js 18)..."
            # Ubuntu 24.04 butuh pendekatan keyring baru
            if [[ "$OS_CODENAME" == "noble" ]]; then
                # Method baru: manual keyring
                curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
                    | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg
                echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] \
https://deb.nodesource.com/node_18.x nodistro main" \
                    > /etc/apt/sources.list.d/nodesource.list
            else
                # Method lama: setup script (Ubuntu 20/22)
                curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
            fi
            apt-get update -qq
        fi

        apt-get install -y nodejs

    else
        # RHEL/CentOS
        curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
        yum install -y nodejs
    fi
}

NODE_OK=false
if command -v node &>/dev/null; then
    CURRENT_NODE=$(node -v 2>/dev/null | grep -oP '\d+' | head -1)
    if [[ "${CURRENT_NODE:-0}" -ge 18 ]]; then
        success "Node.js sudah terinstall: $(node -v) (✓ kompatibel)"
        NODE_OK=true
    else
        warn "Node.js ada tapi versi $(node -v) < 18 — akan diupgrade ke v18..."
    fi
fi

if ! $NODE_OK; then
    install_nodejs_18
    INSTALLED_VER=$(node -v 2>/dev/null || echo "?")
    success "Node.js $INSTALLED_VER terinstall"
fi

# Verifikasi
NODE_MAJOR=$(node -v 2>/dev/null | grep -oP '\d+' | head -1)
[[ "${NODE_MAJOR:-0}" -lt 12 ]] && error "Node.js versi terlalu lama: $(node -v). Butuh minimal v12."

# ════════════════════════════════════════════════════════════
#  INSTALL MONGODB 7.0
#  (Support Ubuntu 20.04 focal / 22.04 jammy / 24.04 noble)
# ════════════════════════════════════════════════════════════
info "=== MongoDB 7.0 ==="

MONGO_VERSION="7.0"
MONGO_GPG_KEY="https://www.mongodb.org/static/pgp/server-${MONGO_VERSION}.asc"
KEYRING_FILE="/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg"
REPO_FILE="/etc/apt/sources.list.d/mongodb-org-${MONGO_VERSION}.list"

install_mongodb() {
    if [[ "$OS_TYPE" == "debian" ]]; then

        # Tambah GPG key
        if [[ ! -f "$KEYRING_FILE" ]]; then
            info "Menambahkan MongoDB GPG key..."
            curl -fsSL "$MONGO_GPG_KEY" | gpg --dearmor -o "$KEYRING_FILE"
        fi

        # Tentukan codename yang didukung MongoDB 7.0
        MONGO_CODENAME="$OS_CODENAME"
        case "$OS_CODENAME" in
            focal|jammy|noble) : ;;   # didukung langsung
            *)
                # Fallback ke focal untuk codename tidak dikenal
                warn "Codename '$OS_CODENAME' tidak dikenal untuk MongoDB, pakai 'focal'"
                MONGO_CODENAME="focal"
                ;;
        esac

        # Tambah repo
        if [[ ! -f "$REPO_FILE" ]]; then
            info "Menambahkan MongoDB $MONGO_VERSION repo ($MONGO_CODENAME)..."
            echo "deb [ arch=amd64,arm64 signed-by=${KEYRING_FILE} ] \
https://repo.mongodb.org/apt/ubuntu ${MONGO_CODENAME}/mongodb-org/${MONGO_VERSION} multiverse" \
                > "$REPO_FILE"
            apt-get update -qq
        fi

        apt-get install -y mongodb-org

    else
        # RHEL/CentOS
        cat > /etc/yum.repos.d/mongodb-org-${MONGO_VERSION}.repo <<EOF
[mongodb-org-${MONGO_VERSION}]
name=MongoDB ${MONGO_VERSION} Repository
baseurl=https://repo.mongodb.org/yum/redhat/\$releasever/mongodb-org/${MONGO_VERSION}/x86_64/
gpgcheck=1
enabled=1
gpgkey=${MONGO_GPG_KEY}
EOF
        yum install -y mongodb-org
    fi
}

if command -v mongod &>/dev/null; then
    MONGO_VER=$(mongod --version 2>&1 | grep -oP 'v\d+\.\d+' | head -1 || echo "?")
    success "MongoDB sudah ada: $MONGO_VER"
else
    install_mongodb
    success "MongoDB $(mongod --version 2>&1 | head -1) terinstall"
fi

# Jalankan & enable MongoDB
if ! systemctl is-active --quiet mongod 2>/dev/null; then
    info "Menjalankan MongoDB..."
    systemctl enable mongod 2>/dev/null || true
    systemctl start mongod
    # Tunggu MongoDB siap
    for i in {1..10}; do
        sleep 1
        if systemctl is-active --quiet mongod 2>/dev/null; then
            break
        fi
        [[ $i -eq 10 ]] && error "MongoDB gagal start! Cek: journalctl -u mongod -n 30"
    done
fi
success "MongoDB running ($(systemctl is-active mongod))"

# ════════════════════════════════════════════════════════════
#  INSTALL MONGORESTORE (mongodb-database-tools)
# ════════════════════════════════════════════════════════════
info "=== mongodb-database-tools (mongorestore) ==="

if ! command -v mongorestore &>/dev/null; then
    info "Menginstall mongodb-database-tools..."
    if [[ "$OS_TYPE" == "debian" ]]; then
        # mongodb-database-tools sudah include di paket mongodb-org di versi baru
        # tapi install eksplisit untuk memastikan
        apt-get install -y mongodb-database-tools 2>/dev/null || \
        apt-get install -y mongodb-org-tools 2>/dev/null || \
        warn "mongodb-database-tools tidak bisa diinstall via apt — coba manual"
    else
        yum install -y mongodb-database-tools 2>/dev/null || \
        warn "mongodb-database-tools tidak bisa diinstall — coba manual"
    fi
fi

if command -v mongorestore &>/dev/null; then
    success "mongorestore: $(mongorestore --version 2>&1 | head -1)"
else
    warn "mongorestore tidak ditemukan! Import MongoDB akan dilewati saat add-instance."
fi

# ════════════════════════════════════════════════════════════
#  DEPLOY GENIEACS APP KE /opt/genieacs-app
# ════════════════════════════════════════════════════════════
info "=== Deploy GenieACS App ==="

if [[ -d "$APP_DST" ]]; then
    OLD="${APP_DST}-old-$(date +%Y%m%d%H%M%S)"
    warn "App lama ditemukan, backup ke: $OLD"
    mv "$APP_DST" "$OLD"
fi

cp -a "$APP_SRC" "$APP_DST"

# Hapus file Windows-only
rm -f "$APP_DST/mongorestore.exe" "$APP_DST/start.bat" "$APP_DST/stop.bat" 2>/dev/null || true
# Hapus backup files
rm -rf "$APP_DST/bin.bak-"* "$APP_DST/public.bak-"* 2>/dev/null || true

success "App di-deploy ke $APP_DST"
info "  GenieACS versi: $(grep '\"version\"' $APP_DST/package.json | grep -oP '[\d.+a-z]+')"

# Install npm dependencies (dibutuhkan jika deploy via git clone)
if [[ ! -d "$APP_DST/node_modules" ]] || [[ ! -d "$APP_DST/node_modules/bson" ]]; then
    info "Menginstall npm dependencies..."
    cd "$APP_DST" && npm install --omit=dev 2>&1 | tail -5
    success "npm dependencies terinstall"
else
    info "node_modules sudah ada, skip npm install"
fi

# ── Buat folder instances ────────────────────────────────────
mkdir -p "$INSTANCES_DIR"
touch "$INSTANCES_DIR/.registry"
success "Folder instances: $INSTANCES_DIR"

# ── Ringkasan ────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}   Setup selesai!${NC}"
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "  OS         : Ubuntu $OS_VER ($OS_CODENAME)"
echo -e "  Node.js    : $(node -v)"
echo -e "  MongoDB    : $(mongod --version 2>&1 | grep -oP 'v[\d.]+' | head -1)"
echo -e "  App dir    : ${CYAN}$APP_DST${NC}"
echo -e "  Instances  : ${CYAN}$INSTANCES_DIR${NC}"
echo ""
echo -e "  ${BOLD}Langkah selanjutnya:${NC}"
echo -e "  ${YELLOW}sudo bash add-instance.sh${NC}     ← tambah instance/user baru"
echo -e "  ${YELLOW}bash list-instances.sh${NC}        ← lihat semua instance"
echo "============================================================"
