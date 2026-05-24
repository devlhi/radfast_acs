#!/bin/bash
# ============================================================
#  GenieACS Multi-Instance — Lihat Semua Instance
#  By RadFast Bill
#  Usage: bash list-instances.sh
# ============================================================

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
DIM='\033[2m'

INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}   GenieACS Multi-Instance — Daftar Instance${NC}"
echo -e "${BOLD}============================================================${NC}"

if [[ ! -f "$REGISTRY" ]] || [[ ! -s "$REGISTRY" ]]; then
    echo -e "  ${YELLOW}Belum ada instance. Jalankan: sudo bash add-instance.sh${NC}"
    echo "============================================================"
    exit 0
fi

COUNT=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    COUNT=$((COUNT + 1))

    NAME=$(echo "$line" | awk '{print $1}')
    UI=$(echo "$line"   | grep -oP 'UI=\K[0-9]+' || echo "?")
    CWMP=$(echo "$line" | grep -oP 'CWMP=\K[0-9]+' || echo "?")
    NBI=$(echo "$line"  | grep -oP 'NBI=\K[0-9]+' || echo "?")
    FS=$(echo "$line"   | grep -oP 'FS=\K[0-9]+' || echo "?")
    DB=$(echo "$line"   | grep -oP 'DB=\K\S+' || echo "?")
    IP=$(echo "$line"   | grep -oP 'IP=\K\S+' || echo "?")
    DATE=$(echo "$line" | grep -oP 'DATE=\K\S+' || echo "?")

    echo ""
    echo -e "  ${BOLD}[$COUNT] ${CYAN}$NAME${NC}  ${DIM}(dibuat: $DATE)${NC}"
    echo -e "  ├─ UI   Dashboard Web      : ${GREEN}http://$IP:$UI${NC}"
    echo -e "  ├─ CWMP Port device TR-069 : $IP:$CWMP"
    echo -e "  ├─ NBI  REST API           : $IP:$NBI"
    echo -e "  ├─ FS   File Server        : $IP:$FS"
    echo -e "  ├─ Database                : $DB"

    echo -e "  ├─ 🖼  Upload Logo             : ${CYAN}http://$IP:$UI/__admin/logo${NC}"

    # Cek status services
    STATUS_LINE=""
    for SVC in cwmp fs nbi ui proxy; do
        if systemctl is-active --quiet "genieacs-${NAME}-${SVC}" 2>/dev/null; then
            STATUS_LINE+="${GREEN}${SVC}✓${NC} "
        else
            STATUS_LINE+="${RED}${SVC}✗${NC} "
        fi
    done
    echo -e "  └─ Status  : $STATUS_LINE"

done < "$REGISTRY"

echo ""
echo -e "${BOLD}  Total: $COUNT instance${NC}"
echo ""
echo -e "  ${DIM}Tambah  : sudo bash add-instance.sh${NC}"
echo -e "  ${DIM}Hapus   : sudo bash remove-instance.sh <username>${NC}"
echo -e "  ${DIM}Log     : journalctl -u genieacs-<user>-ui -f${NC}"
echo "============================================================"
echo ""
