#!/bin/bash
# ============================================================
#  RadFast ACS — Seed / Re-seed Instance Database
#  Berguna untuk instance yang DB-nya kosong (login GenieACS gagal /
#  dashboard cuma redirect ke /login) karena import waktu add-instance
#  dilewati (mongorestore tidak ada, atau Node fallback gagal load
#  dependency).
#
#  Usage: sudo bash seed-instance.sh <username>
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash seed-instance.sh <username>"

APP_DIR="/opt/genieacs-app"
INSTANCES_DIR="/opt/genieacs-instances"
REPO_DIR="/opt/radfast_acs"
CONF_DIR="$APP_DIR/conf-acs"

[[ ! -d "$CONF_DIR" ]] && error "conf-acs tidak ada di $CONF_DIR — tidak bisa seed."

USERNAME="${1:-}"
[[ -z "$USERNAME" ]] && error "Usage: sudo bash seed-instance.sh <username>"
USERNAME=$(echo "$USERNAME" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
[[ -z "$USERNAME" ]] && error "Username tidak valid!"

DB_NAME="genieacs_${USERNAME}"
INST_DIR="$INSTANCES_DIR/$USERNAME"

# Sanity check: minimal salah satu harus ada (folder atau registry entry).
# Kalau folder masih ada, ambil DB_NAME dari .env supaya akurat saat user
# pakai DB name custom.
if [[ -f "$INST_DIR/.env" ]]; then
    ENV_DB=$(grep -oP 'GENIEACS_MONGODB_CONNECTION_URL=mongodb://[^/]+/\K[a-zA-Z0-9_]+' "$INST_DIR/.env" 2>/dev/null || true)
    [[ -n "$ENV_DB" ]] && DB_NAME="$ENV_DB"
fi

echo ""
echo -e "${BOLD}  Seed database untuk instance:${NC}"
echo -e "  User     : ${CYAN}$USERNAME${NC}"
echo -e "  Database : ${CYAN}$DB_NAME${NC}"
echo -e "  Source   : ${CYAN}$CONF_DIR${NC}"
echo ""
echo -e "${YELLOW}  ⚠  Koleksi yang ada di $DB_NAME akan di-DROP & di-replace dari seed.${NC}"
echo ""
read -rp "$(echo -e "${YELLOW}Lanjutkan? [y/N]: ${NC}")" CONFIRM
[[ ! "${CONFIRM:-N}" =~ ^[Yy]$ ]] && echo "Dibatalkan." && exit 0

# ── Coba mongorestore dulu (paling robust) ───────────────────
if command -v mongorestore &>/dev/null; then
    info "Import via mongorestore..."
    mongorestore --db "$DB_NAME" --drop "$CONF_DIR" 2>&1 \
        | grep -E "done|error|finish|inserted|documents" || true
    success "Database $DB_NAME ter-seed via mongorestore"
    exit 0
fi

# ── Fallback: importer Node ──────────────────────────────────
NODE_BIN=$(command -v node 2>/dev/null || echo "/usr/bin/node")
[[ ! -f "$NODE_BIN" ]] && error "node binary tidak ditemukan!"

IMPORT_SCRIPT=""
for loc in "$REPO_DIR/import-bson.js" "$(dirname "$0")/import-bson.js" "/opt/radfast_acs/import-bson.js"; do
    [[ -f "$loc" ]] && IMPORT_SCRIPT="$loc" && break
done
[[ -z "$IMPORT_SCRIPT" ]] && error "import-bson.js tidak ditemukan dan mongorestore juga tidak ada."

warn "mongorestore tidak ada — pakai fallback Node: $IMPORT_SCRIPT"
info "Import via Node ke $DB_NAME..."
if RADFAST_APP_DIR="$APP_DIR" "$NODE_BIN" "$IMPORT_SCRIPT" "$CONF_DIR" "$DB_NAME" "mongodb://127.0.0.1:27017"; then
    success "Database $DB_NAME ter-seed via Node fallback"
    echo ""
    echo -e "${GREEN}${BOLD}  Selesai.${NC} Coba akses dashboard GenieACS instance '${USERNAME}'."
    echo -e "  Login default: ${CYAN}admin${NC} (cek catatan kamu untuk passwordnya)."
else
    error "Seed gagal — cek log error di atas."
fi
