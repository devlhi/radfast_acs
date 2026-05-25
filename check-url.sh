#!/bin/bash
# ============================================================
#  RadFast ACS — Cek URL & Port Semua Instance
#  Usage: bash check-url.sh [username]
# ============================================================

GREEN='\033[0;32m'; RED='\033[0;31m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"
FILTER="${1:-}"
TIMEOUT=3   # detik per request curl
OK=0; FAIL=0

check_http() {
    local url="$1"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "$url" 2>/dev/null)
    echo "$code"
}

check_port() {
    local host="$1" port="$2"
    # TCP connect saja (untuk CWMP, NBI, FS yang tidak harus return HTML)
    if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        echo "open"
    else
        echo "closed"
    fi
}

print_row() {
    local label="$1" url="$2" type="$3" allow404="${4:-no}"
    local result icon

    if [[ "$type" == "http" ]]; then
        result=$(check_http "$url")
        # 404 dianggap OK untuk NBI/FS — mereka tidak serve root /, tapi service jalan
        local ok_codes="200 302 301 401"
        [[ "$allow404" == "yes" ]] && ok_codes="$ok_codes 404"
        if echo "$ok_codes" | grep -qw "$result"; then
            icon="${GREEN}●${NC}"
            OK=$((OK+1))
            local note=""
            [[ "$result" == "404" ]] && note=" ${DIM}(root / tidak ada, normal)${NC}"
            printf "  ${icon} %-22s ${CYAN}%-32s${NC} ${GREEN}HTTP $result${NC}${note}\n" "$label" "$url"
        else
            icon="${RED}●${NC}"
            FAIL=$((FAIL+1))
            local reason="down/timeout"
            [[ "$result" == "000" ]] && reason="koneksi ditolak/timeout"
            printf "  ${icon} %-22s ${CYAN}%-32s${NC} ${RED}HTTP $result ($reason)${NC}\n" "$label" "$url"
        fi
    else
        local host port
        host="${url%%:*}"
        port="${url##*:}"
        result=$(check_port "$host" "$port")
        if [[ "$result" == "open" ]]; then
            icon="${GREEN}●${NC}"
            OK=$((OK+1))
            printf "  ${icon} %-22s ${CYAN}%-32s${NC} ${GREEN}port open${NC}\n" "$label" "$url"
        else
            icon="${RED}●${NC}"
            FAIL=$((FAIL+1))
            printf "  ${icon} %-22s ${CYAN}%-32s${NC} ${RED}port closed${NC}\n" "$label" "$url"
        fi
    fi
}

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "${BOLD}   RadFast ACS — Cek URL & Port   $(date '+%H:%M:%S')${NC}"
echo -e "${BOLD}============================================================${NC}"

if [[ ! -f "$REGISTRY" ]] || [[ ! -s "$REGISTRY" ]]; then
    echo -e "  ${YELLOW}Belum ada instance terdaftar.${NC}"
    exit 0
fi

while IFS= read -r line; do
    [[ -z "$line" ]] && continue

    NAME=$(echo "$line" | awk '{print $1}')
    [[ -n "$FILTER" && "$NAME" != "$FILTER" ]] && continue

    UI=$(echo "$line"   | grep -oP 'UI=\K[0-9]+')
    CWMP=$(echo "$line" | grep -oP 'CWMP=\K[0-9]+')
    NBI=$(echo "$line"  | grep -oP 'NBI=\K[0-9]+')
    FS=$(echo "$line"   | grep -oP 'FS=\K[0-9]+')
    IP=$(echo "$line"   | grep -oP 'IP=\K\S+')

    echo ""
    echo -e "  ${BOLD}▶ $NAME${NC}  —  http://${IP}:${UI}"
    echo -e "  ─────────────────────────────────────────────────────"

    print_row "UI (Dashboard)"  "http://${IP}:${UI}"   "http" "no"
    print_row "CWMP (TR-069)"   "${IP}:${CWMP}"        "tcp"  "no"
    print_row "NBI  (REST API)" "http://${IP}:${NBI}"  "http" "yes"
    print_row "FS   (File Svr)" "http://${IP}:${FS}"   "http" "yes"

    # Diagnosis otomatis kalau UI down
    if [[ "$(check_http "http://${IP}:${UI}")" == "000" ]]; then
        echo -e "  ${YELLOW}  ⚠ UI down — cek:${NC}"
        echo -e "  ${DIM}    systemctl status genieacs-${NAME}-proxy${NC}"
        echo -e "  ${DIM}    systemctl status genieacs-${NAME}-ui${NC}"
        echo -e "  ${DIM}    journalctl -u genieacs-${NAME}-proxy -n 20${NC}"
    fi

done < "$REGISTRY"

echo ""
echo -e "${BOLD}============================================================${NC}"
echo -e "  Hasil: ${GREEN}$OK OK${NC}  /  ${RED}$FAIL GAGAL${NC}"
echo -e "${BOLD}============================================================${NC}"
echo ""
