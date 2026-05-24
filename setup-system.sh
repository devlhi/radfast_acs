#!/bin/bash
# ============================================================
#  GenieACS Multi-Instance — System Setup (jalankan SEKALI)
#  Support: Ubuntu 20.04 / 22.04 / 24.04 / RHEL / CentOS
#  Node.js : 20 LTS
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${SCRIPT_DIR}"   # folder repo = folder script ini berada
APP_DST="/opt/genieacs-app"
INSTANCES_DIR="/opt/genieacs-instances"

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
#  INSTALL NODE.JS 20 LTS
# ════════════════════════════════════════════════════════════
info "=== Node.js 20 LTS ==="

install_nodejs_18() {
    if [[ "$OS_TYPE" == "debian" ]]; then

        # Hapus repo NodeSource lama (node 18) jika ada, supaya tidak konflik
        rm -f /etc/apt/sources.list.d/nodesource.list \
              /etc/apt/sources.list.d/nodejs*.list \
              /usr/share/keyrings/nodesource.gpg 2>/dev/null || true

        # Deteksi apakah NodeSource sudah di-setup untuk node 20
        if grep -r "node_20\|node/20" /etc/apt/sources.list.d/ &>/dev/null 2>&1; then
            info "NodeSource repo Node 20 sudah ada, skip setup"
        else
            info "Menambahkan NodeSource repo (Node.js 20)..."
            # Ubuntu 24.04 butuh pendekatan keyring baru
            if [[ "$OS_CODENAME" == "noble" || "$OS_CODENAME" == "jammy" || "$OS_CODENAME" == "focal" ]]; then
                # Method baru: manual keyring (berlaku untuk semua Ubuntu)
                curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
                    | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg
                echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] \
https://deb.nodesource.com/node_20.x nodistro main" \
                    > /etc/apt/sources.list.d/nodesource.list
            else
                # Fallback: setup script
                curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
            fi
            apt-get update -qq
        fi

        apt-get install -y nodejs

    else
        # RHEL/CentOS
        curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
        yum install -y nodejs
    fi
}

NODE_OK=false
if command -v node &>/dev/null; then
    CURRENT_NODE=$(node -v 2>/dev/null | grep -oP '\d+' | head -1)
    if [[ "${CURRENT_NODE:-0}" -ge 20 ]]; then
        success "Node.js sudah terinstall: $(node -v) (✓ kompatibel)"
        NODE_OK=true
    elif [[ "${CURRENT_NODE:-0}" -ge 18 ]]; then
        warn "Node.js $(node -v) terinstall tapi < v20 — akan diupgrade ke v20..."
    else
        warn "Node.js ada tapi versi $(node -v) < 18 — akan diupgrade ke v20..."
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
#  INSTALL MONGODB
#  - Ubuntu 20.04 (focal)  → MongoDB 7.0
#  - Ubuntu 22.04 (jammy)  → MongoDB 7.0
#  - Ubuntu 24.04 (noble)  → MongoDB 8.0 (7.0 tidak support noble)
# ════════════════════════════════════════════════════════════

# Pilih versi MongoDB sesuai OS
case "$OS_CODENAME" in
    noble) MONGO_VERSION="8.0" ;;
    *)     MONGO_VERSION="7.0" ;;
esac

info "=== MongoDB ${MONGO_VERSION} ==="

MONGO_GPG_KEY="https://www.mongodb.org/static/pgp/server-${MONGO_VERSION}.asc"
KEYRING_FILE="/usr/share/keyrings/mongodb-server-${MONGO_VERSION}.gpg"
REPO_FILE="/etc/apt/sources.list.d/mongodb-org-${MONGO_VERSION}.list"

install_mongodb() {
    if [[ "$OS_TYPE" == "debian" ]]; then

        # Hapus repo MongoDB versi lain yang mungkin konflik
        for OLD_VER in 6.0 7.0 8.0; do
            [[ "$OLD_VER" == "$MONGO_VERSION" ]] && continue
            rm -f "/etc/apt/sources.list.d/mongodb-org-${OLD_VER}.list" \
                  "/usr/share/keyrings/mongodb-server-${OLD_VER}.gpg" 2>/dev/null || true
        done

        # Tambah GPG key
        if [[ ! -f "$KEYRING_FILE" ]]; then
            info "Menambahkan MongoDB GPG key..."
            curl -fsSL "$MONGO_GPG_KEY" | gpg --dearmor -o "$KEYRING_FILE"
        fi

        # Tentukan codename
        MONGO_CODENAME="$OS_CODENAME"
        case "$OS_CODENAME" in
            focal|jammy|noble) : ;;
            *)
                warn "Codename '$OS_CODENAME' tidak dikenal untuk MongoDB, pakai 'jammy'"
                MONGO_CODENAME="jammy"
                ;;
        esac

        # Tambah repo
        if [[ ! -f "$REPO_FILE" ]]; then
            info "Menambahkan MongoDB ${MONGO_VERSION} repo ($MONGO_CODENAME)..."
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
    MONGO_VER=$(mongod --version 2>&1 | grep -oP '\d+\.\d+' | head -1 || echo "0")
    MONGO_MAJOR=$(echo "$MONGO_VER" | cut -d. -f1)
    MONGO_NEED=$(echo "$MONGO_VERSION" | cut -d. -f1)
    if [[ "${MONGO_MAJOR:-0}" -ge "${MONGO_NEED:-7}" ]]; then
        success "MongoDB sudah ada: v$MONGO_VER (✓ kompatibel)"
    else
        warn "MongoDB v$MONGO_VER < v${MONGO_VERSION} — upgrade..."
        install_mongodb
        success "MongoDB diupgrade ke $(mongod --version 2>&1 | head -1)"
    fi
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

# ── Buat shortcut command global ─────────────────────────────
info "Membuat shortcut command global..."
declare -A CMDS=(
    ["radfast-status"]="$REPO_DIR/status.sh"
    ["radfast-add"]="$REPO_DIR/add-instance.sh"
    ["radfast-remove"]="$REPO_DIR/remove-instance.sh"
    ["radfast-list"]="$REPO_DIR/list-instances.sh"
)
for CMD in "${!CMDS[@]}"; do
    TARGET="${CMDS[$CMD]}"
    LINK="/usr/local/bin/$CMD"
    # Buat wrapper script (bukan symlink) supaya bash tetap bisa jalankan
    cat > "$LINK" <<WRAPPER
#!/bin/bash
exec bash "$TARGET" "\$@"
WRAPPER
    chmod +x "$LINK"
    success "Shortcut: $CMD  →  $TARGET"
done

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
echo -e "  ${BOLD}Shortcut command (bisa dijalankan dari mana saja):${NC}"
echo -e "  ${CYAN}radfast-status${NC}   ← lihat status instance + resource"
echo -e "  ${CYAN}radfast-list${NC}     ← lihat daftar semua instance"
echo -e "  ${CYAN}radfast-add${NC}      ← tambah instance/user baru"
echo -e "  ${CYAN}radfast-remove${NC}   ← hapus instance"
echo ""
echo -e "  ${BOLD}Atau dengan path lengkap:${NC}"
echo -e "  ${YELLOW}sudo bash add-instance.sh${NC}     ← tambah instance/user baru"
echo -e "  ${YELLOW}bash list-instances.sh${NC}        ← lihat semua instance"
echo "============================================================"
