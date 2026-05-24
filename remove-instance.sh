#!/bin/bash
# ============================================================
#  GenieACS Multi-Instance — Hapus Instance
#  Support: Ubuntu 20.04 / 22.04 / 24.04 / RHEL / CentOS
#  By RadFast Bill
#  Usage: sudo bash remove-instance.sh <username>
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash remove-instance.sh <username>"

INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"

# ── Input username ───────────────────────────────────────────
if [[ -n "${1:-}" ]]; then
    USERNAME="$1"
else
    echo ""
    if [[ -f "$REGISTRY" ]] && [[ -s "$REGISTRY" ]]; then
        echo -e "${BOLD}  Instance yang ada:${NC}"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            NAME=$(echo "$line" | awk '{print $1}')
            UI=$(echo "$line" | grep -oP 'UI=\K[0-9]+' || echo "?")
            echo -e "  - ${CYAN}$NAME${NC}  (UI port: $UI)"
        done < "$REGISTRY"
        echo ""
    else
        echo -e "  ${YELLOW}Tidak ada instance.${NC}"; exit 0
    fi
    read -rp "$(echo -e "${CYAN}[INPUT]${NC} Username instance yang akan dihapus: ")" USERNAME
fi

USERNAME=$(echo "$USERNAME" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
[[ -z "$USERNAME" ]]              && error "Username tidak valid!"
[[ ! -d "$INSTANCES_DIR/$USERNAME" ]] && error "Instance '$USERNAME' tidak ditemukan!"

INST_DIR="$INSTANCES_DIR/$USERNAME"
DB_NAME="genieacs_${USERNAME}"

# Ambil info dari .env
UI_PORT=$(grep -oP 'GENIEACS_UI_PORT=\K[0-9]+' "$INST_DIR/.env" 2>/dev/null || echo "?")
CWMP_PORT=$(grep -oP 'GENIEACS_CWMP_PORT=\K[0-9]+' "$INST_DIR/.env" 2>/dev/null || echo "?")

# ── Konfirmasi ───────────────────────────────────────────────
echo ""
echo -e "${RED}${BOLD}  ⚠ HAPUS instance '${USERNAME}'?${NC}"
echo -e "  Folder   : $INST_DIR"
echo -e "  Database : $DB_NAME"
echo -e "  UI Port  : $UI_PORT"
echo -e "  CWMP Port: $CWMP_PORT"
echo ""
echo -e "${RED}  Data MongoDB AKAN DIHAPUS PERMANEN!${NC}"
echo ""
read -rp "$(echo -e "${RED}Ketik nama instance untuk konfirmasi: ${NC}")" CONFIRM_NAME
[[ "$CONFIRM_NAME" != "$USERNAME" ]] && echo "Nama tidak cocok, dibatalkan." && exit 0

# ── Stop & disable services ──────────────────────────────────
info "Menghentikan services..."
for SVC in ui nbi fs cwmp; do
    SVCNAME="genieacs-${USERNAME}-${SVC}"
    if systemctl list-units --full --all 2>/dev/null | grep -q "$SVCNAME"; then
        systemctl stop    "$SVCNAME" 2>/dev/null || true
        systemctl disable "$SVCNAME" 2>/dev/null || true
    fi
    rm -f "/etc/systemd/system/${SVCNAME}.service"
done
systemctl daemon-reload
success "Services dihapus"

# ── Hapus MongoDB database ───────────────────────────────────
info "Menghapus database MongoDB: $DB_NAME..."

drop_db_cmd="db.getSiblingDB('${DB_NAME}').dropDatabase()"

if command -v mongosh &>/dev/null; then
    # MongoDB 6+ pakai mongosh
    mongosh --quiet --eval "$drop_db_cmd" 2>/dev/null && \
        success "Database $DB_NAME dihapus (via mongosh)" || \
        warn "Gagal hapus DB. Manual: mongosh --eval \"$drop_db_cmd\""

elif command -v mongo &>/dev/null; then
    # MongoDB 4/5 pakai mongo
    mongo --quiet --eval "$drop_db_cmd" 2>/dev/null && \
        success "Database $DB_NAME dihapus (via mongo)" || \
        warn "Gagal hapus DB. Manual: mongo --eval \"$drop_db_cmd\""

else
    warn "mongosh/mongo tidak ditemukan."
    warn "Hapus manual: mongosh → use $DB_NAME → db.dropDatabase()"
fi

# ── Hapus folder instance ────────────────────────────────────
rm -rf "$INST_DIR"
success "Folder $INST_DIR dihapus"

# ── Update registry ──────────────────────────────────────────
if [[ -f "$REGISTRY" ]]; then
    grep -v "^${USERNAME} " "$REGISTRY" > "${REGISTRY}.tmp" 2>/dev/null \
        && mv "${REGISTRY}.tmp" "$REGISTRY" || rm -f "${REGISTRY}.tmp"
fi
success "Registry diupdate"

echo ""
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}   Instance '${USERNAME}' berhasil dihapus${NC}"
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "  Lihat sisa: ${YELLOW}bash list-instances.sh${NC}"
echo "============================================================"
