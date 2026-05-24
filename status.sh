#!/bin/bash
# ============================================================
#  RadFast ACS — Status Monitor
#  Lihat instance aktif + penggunaan disk/memory/CPU
#  Usage: bash /opt/radfast_acs/status.sh
# ============================================================

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'; DIM='\033[2m'

APP_DIR="/opt/genieacs-app"
INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}   RadFast ACS — Status Monitor${NC}"
echo -e "${BOLD}   $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}============================================================${NC}"

# ── Disk: App & Instances ─────────────────────────────────────
echo ""
echo -e "${BOLD}📦 Penggunaan Disk:${NC}"

APP_SIZE=$(du -sh "$APP_DIR" 2>/dev/null | cut -f1 || echo "?")
echo -e "  GenieACS App  (/opt/genieacs-app)     : ${CYAN}$APP_SIZE${NC}"

if [[ -d "$INSTANCES_DIR" ]]; then
    INST_TOTAL=$(du -sh "$INSTANCES_DIR" 2>/dev/null | cut -f1 || echo "?")
    echo -e "  Semua Instance (/opt/genieacs-instances): ${CYAN}$INST_TOTAL${NC}"
fi

# Disk VPS keseluruhan
DISK_INFO=$(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" ("$5" terpakai)"}')
echo -e "  VPS Total                              : ${CYAN}$DISK_INFO${NC}"

# ── RAM & Load ────────────��───────────────────────────────────
echo ""
echo -e "${BOLD}💾 Memory & Load:${NC}"
RAM_INFO=$(free -h 2>/dev/null | awk '/^Mem/{print $3"/"$2" (cache: "$6")"}' || echo "?")
LOAD=$(uptime 2>/dev/null | grep -oP 'load average: \K.+' || echo "?")
echo -e "  RAM   : ${CYAN}$RAM_INFO${NC}"
echo -e "  Load  : ${CYAN}$LOAD${NC}"

# ── MongoDB ──────────────��──────────────────────���─────────────
echo ""
echo -e "${BOLD}🗄  MongoDB:${NC}"
if systemctl is-active --quiet mongod 2>/dev/null; then
    echo -e "  mongod: ${GREEN}running${NC}"
    # Ukuran tiap database GenieACS
    MONGO_CMD='db.adminCommand({listDatabases:1}).databases
        .filter(d=>d.name.startsWith("genieacs"))
        .forEach(d=>print(d.name+"\t"+Math.round(d.sizeOnDisk/1024/1024*10)/10+"MB"))'

    if command -v mongosh &>/dev/null; then
        DBLIST=$(mongosh --quiet --eval "$MONGO_CMD" 2>/dev/null || echo "")
    elif command -v mongo &>/dev/null; then
        DBLIST=$(mongo --quiet --eval "$MONGO_CMD" 2>/dev/null || echo "")
    else
        DBLIST=""
    fi

    if [[ -n "$DBLIST" ]]; then
        while IFS=$'\t' read -r dbname dbsize; do
            [[ -z "$dbname" ]] && continue
            printf "  %-35s: ${CYAN}%s${NC}\n" "$dbname" "$dbsize"
        done <<< "$DBLIST"
    else
        echo -e "  ${DIM}(tidak bisa baca ukuran DB)${NC}"
    fi
else
    echo -e "  mongod: ${RED}stopped!${NC}"
fi

# ── Instance List ─���───────────────────────────────────────────
echo ""
echo -e "${BOLD}🖥  Instance:${NC}"

if [[ ! -f "$REGISTRY" ]] || [[ ! -s "$REGISTRY" ]]; then
    echo -e "  ${YELLOW}Belum ada instance.${NC}"
else
    COUNT=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        COUNT=$((COUNT + 1))

        NAME=$(echo "$line" | awk '{print $1}')
        UI=$(echo "$line"   | grep -oP 'UI=\K[0-9]+')
        CWMP=$(echo "$line" | grep -oP 'CWMP=\K[0-9]+')
        IP=$(echo "$line"   | grep -oP 'IP=\K\S+')

        echo ""
        echo -e "  ${BOLD}[$COUNT] $NAME${NC}  —  http://$IP:$UI"

        # Status tiap service
        ALL_UP=true
        for SVC in cwmp fs nbi ui proxy; do
            SVCNAME="genieacs-${NAME}-${SVC}"
            if systemctl is-active --quiet "$SVCNAME" 2>/dev/null; then
                STATUS="${GREEN}✓${NC}"
            else
                STATUS="${RED}✗${NC}"
                ALL_UP=false
            fi
            printf "    %-8s %b  " "$SVC" "$STATUS"
        done
        echo ""

        # CPU & RAM proses Node.js instance ini
        PIDS=$(pgrep -f "genieacs-${NAME}" 2>/dev/null || true)
        if [[ -n "$PIDS" ]]; then
            CPU_TOT=0; MEM_TOT=0
            while IFS= read -r pid; do
                [[ -z "$pid" ]] && continue
                LINE=$(ps -p "$pid" -o %cpu=,%mem= 2>/dev/null || true)
                CPU=$(echo "$LINE" | awk '{print $1}')
                MEM=$(echo "$LINE" | awk '{print $2}')
                CPU_TOT=$(awk "BEGIN{print $CPU_TOT + ${CPU:-0}}")
                MEM_TOT=$(awk "BEGIN{print $MEM_TOT + ${MEM:-0}}")
            done <<< "$PIDS"
            MEM_MB=$(awk "BEGIN{printf \"%.0f\", $MEM_TOT * $(grep MemTotal /proc/meminfo | awk '{print $2}') / 100 / 1024}")
            echo -e "    CPU: ${CYAN}${CPU_TOT}%${NC}  RAM: ${CYAN}${MEM_MB} MB${NC}"
        else
            echo -e "    ${DIM}(tidak ada proses berjalan)${NC}"
        fi

        # Disk folder instance
        INST_SIZE=$(du -sh "$INSTANCES_DIR/$NAME" 2>/dev/null | cut -f1 || echo "?")
        echo -e "    Disk folder: ${CYAN}$INST_SIZE${NC}"

    done < "$REGISTRY"

    echo ""
    echo -e "  ${BOLD}Total: $COUNT instance${NC}"
fi

# ── Quick commands ────────────────────────────────────────────
echo ""
echo -e "${BOLD}⚡ Perintah Cepat:${NC}"
echo -e "  ${DIM}Tambah instance : sudo bash /opt/radfast_acs/add-instance.sh${NC}"
echo -e "  ${DIM}Hapus instance  : sudo bash /opt/radfast_acs/remove-instance.sh <user>${NC}"
echo -e "  ${DIM}Log instance    : journalctl -u genieacs-<user>-ui -f${NC}"
echo -e "  ${DIM}Restart semua   : systemctl restart genieacs-<user>-{cwmp,fs,nbi,ui,proxy}${NC}"
echo "============================================================"
echo ""
