#!/bin/bash
# ============================================================
#  RadFast ACS — Status Monitor
#  Lihat instance aktif + penggunaan disk/memory/CPU
#  Usage:
#    radfast-status              ← semua instance
#    radfast-status <username>   ← instance tertentu saja
# ============================================================

GREEN='\033[0;32m'; CYAN='\033[0;36m'; RED='\033[0;31m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'; DIM='\033[2m'

APP_DIR="/opt/genieacs-app"
INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"

# ── Filter: jika ada argument, hanya tampil instance itu ─────
FILTER="${1:-}"
if [[ -n "$FILTER" ]]; then
    FILTER=$(echo "$FILTER" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')
fi

echo ""
echo -e "${BOLD}============================================================${NC}"
if [[ -n "$FILTER" ]]; then
    echo -e "${BOLD}   RadFast ACS — Status Instance: ${CYAN}$FILTER${NC}"
else
    echo -e "${BOLD}   RadFast ACS — Status Monitor${NC}"
fi
echo -e "${BOLD}   $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}============================================================${NC}"

# ── Bagian global hanya tampil kalau tidak ada filter ────────
if [[ -z "$FILTER" ]]; then

    # ── Disk: App & Instances ─────────────────────────────────
    echo ""
    echo -e "${BOLD}📦 Penggunaan Disk:${NC}"

    APP_SIZE=$(du -sh "$APP_DIR" 2>/dev/null | cut -f1 || echo "?")
    echo -e "  GenieACS App  (/opt/genieacs-app)     : ${CYAN}$APP_SIZE${NC}"

    if [[ -d "$INSTANCES_DIR" ]]; then
        INST_TOTAL=$(du -sh "$INSTANCES_DIR" 2>/dev/null | cut -f1 || echo "?")
        echo -e "  Semua Instance (/opt/genieacs-instances): ${CYAN}$INST_TOTAL${NC}"
    fi

    DISK_INFO=$(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" ("$5" terpakai)"}')
    echo -e "  VPS Total                              : ${CYAN}$DISK_INFO${NC}"

    # ── RAM & Load ────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}💾 Memory & Load:${NC}"
    RAM_INFO=$(free -h 2>/dev/null | awk '/^Mem/{print $3"/"$2" (cache: "$6")"}' || echo "?")
    LOAD=$(uptime 2>/dev/null | grep -oP 'load average: \K.+' || echo "?")
    echo -e "  RAM   : ${CYAN}$RAM_INFO${NC}"
    echo -e "  Load  : ${CYAN}$LOAD${NC}"

    # ── MongoDB ───────────────────────────────────────────────
    echo ""
    echo -e "${BOLD}🗄  MongoDB:${NC}"
    if systemctl is-active --quiet mongod 2>/dev/null; then
        echo -e "  mongod: ${GREEN}running${NC}"
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

fi  # end global section

# ── Instance List ─────────────────────────────────────────────
echo ""
if [[ -n "$FILTER" ]]; then
    echo -e "${BOLD}🖥  Instance: ${CYAN}$FILTER${NC}"
else
    echo -e "${BOLD}🖥  Instance:${NC}"
fi

if [[ ! -f "$REGISTRY" ]] || [[ ! -s "$REGISTRY" ]]; then
    echo -e "  ${YELLOW}Belum ada instance.${NC}"
else
    COUNT=0
    FOUND=0

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        NAME=$(echo "$line" | awk '{print $1}')

        # Skip jika ada filter dan nama tidak cocok
        if [[ -n "$FILTER" && "$NAME" != "$FILTER" ]]; then
            COUNT=$((COUNT + 1))
            continue
        fi

        COUNT=$((COUNT + 1))
        FOUND=$((FOUND + 1))

        UI=$(echo "$line"   | grep -oP 'UI=\K[0-9]+')
        CWMP=$(echo "$line" | grep -oP 'CWMP=\K[0-9]+')
        NBI=$(echo "$line"  | grep -oP 'NBI=\K[0-9]+')
        FS=$(echo "$line"   | grep -oP 'FS=\K[0-9]+')
        IP=$(echo "$line"   | grep -oP 'IP=\K\S+')
        DATE=$(echo "$line" | grep -oP 'DATE=\K\S+')
        DB=$(echo "$line"   | grep -oP 'DB=\K\S+')

        echo ""
        echo -e "  ${BOLD}$NAME${NC}  —  http://$IP:$UI  ${DIM}(dibuat: $DATE)${NC}"
        echo -e "  ├─ UI   Dashboard  : ${CYAN}http://$IP:$UI${NC}"
        echo -e "  ├─ CWMP TR-069     : $IP:$CWMP"
        echo -e "  ├─ NBI  REST API   : $IP:$NBI"
        echo -e "  ├─ FS   File Server: $IP:$FS"
        echo -e "  ├─ Database        : $DB"

        # Status tiap service
        echo -n "  ├─ Services        : "
        ALL_UP=true
        for SVC in cwmp fs nbi ui proxy; do
            SVCNAME="genieacs-${NAME}-${SVC}"
            if systemctl is-active --quiet "$SVCNAME" 2>/dev/null; then
                echo -ne "${GREEN}${SVC}✓${NC} "
            else
                echo -ne "${RED}${SVC}✗${NC} "
                ALL_UP=false
            fi
        done
        echo ""

        # CPU & RAM
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
            echo -e "  ├─ CPU / RAM       : ${CYAN}${CPU_TOT}%${NC} / ${CYAN}${MEM_MB} MB${NC}"
        else
            echo -e "  ├─ CPU / RAM       : ${DIM}(tidak ada proses berjalan)${NC}"
        fi

        # Disk folder instance
        INST_SIZE=$(du -sh "$INSTANCES_DIR/$NAME" 2>/dev/null | cut -f1 || echo "?")
        echo -e "  └─ Disk folder     : ${CYAN}$INST_SIZE${NC}"

        # Log shortcut khusus instance ini
        if [[ -n "$FILTER" ]]; then
            echo ""
            echo -e "  ${BOLD}⚡ Manage $NAME:${NC}"
            echo -e "  ${DIM}Log UI    : journalctl -u genieacs-${NAME}-ui -f${NC}"
            echo -e "  ${DIM}Log CWMP  : journalctl -u genieacs-${NAME}-cwmp -f${NC}"
            echo -e "  ${DIM}Restart   : systemctl restart genieacs-${NAME}-{cwmp,fs,nbi,ui}${NC}"
            echo -e "  ${DIM}Hapus     : sudo radfast-remove ${NAME}${NC}"
        fi

    done < "$REGISTRY"

    # Pesan jika filter tidak ditemukan
    if [[ -n "$FILTER" && $FOUND -eq 0 ]]; then
        echo ""
        echo -e "  ${RED}Instance '${FILTER}' tidak ditemukan!${NC}"
        echo -e "  Gunakan ${YELLOW}radfast-list${NC} untuk lihat semua instance."
    fi

    if [[ -z "$FILTER" ]]; then
        echo ""
        echo -e "  ${BOLD}Total: $COUNT instance${NC}"
    fi
fi

# ── Quick commands (hanya tampil di mode semua) ───────────────
if [[ -z "$FILTER" ]]; then
    echo ""
    echo -e "${BOLD}⚡ Perintah Cepat:${NC}"
    echo -e "  ${DIM}Status instance  : radfast-status <username>${NC}"
    echo -e "  ${DIM}Tambah instance  : sudo radfast-add${NC}"
    echo -e "  ${DIM}Hapus instance   : sudo radfast-remove <user>${NC}"
    echo -e "  ${DIM}Log instance     : journalctl -u genieacs-<user>-ui -f${NC}"
    echo -e "  ${DIM}Restart proxy : sudo systemctl restart genieacs-multi-proxy${NC}"
    echo -e "  ${DIM}Restart semua : systemctl restart genieacs-<user>-{cwmp,fs,nbi,ui}${NC}"
fi
echo "============================================================"
echo ""
