#!/bin/bash
# ============================================================
#  GenieACS Multi-Instance — Bersihkan SEMUA Instance
#  Support: Ubuntu 20.04 / 22.04 / 24.04 / RHEL / CentOS
#  By RadFast Bill
#  Usage: sudo bash remove-all.sh [--keep-db] [--yes]
#
#  Menghapus:
#   - Semua service genieacs-<user>-{cwmp,fs,nbi,ui,proxy}
#   - Service genieacs-multi-proxy
#   - Semua database MongoDB genieacs_<user>  (kecuali --keep-db)
#   - Semua folder /opt/genieacs-instances/<user>
#   - Registry /opt/genieacs-instances/.registry
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Jalankan sebagai root: sudo bash remove-all.sh"

INSTANCES_DIR="/opt/genieacs-instances"
REGISTRY="$INSTANCES_DIR/.registry"

# ── Parse argumen ────────────────────────────────────────────
KEEP_DB="no"
ASSUME_YES="no"
for arg in "$@"; do
    case "$arg" in
        --keep-db) KEEP_DB="yes" ;;
        --yes|-y)  ASSUME_YES="yes" ;;
        *) warn "Argumen tidak dikenal: $arg" ;;
    esac
done

# ── Kumpulkan daftar instance ────────────────────────────────
# Sumber utama: folder di INSTANCES_DIR. Registry dipakai sebagai pelengkap.
declare -a INSTANCES=()
if [[ -d "$INSTANCES_DIR" ]]; then
    while IFS= read -r dir; do
        [[ -z "$dir" ]] && continue
        name="$(basename "$dir")"
        [[ "$name" == ".registry" ]] && continue
        INSTANCES+=("$name")
    done < <(find "$INSTANCES_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null)
fi

# Tambahkan instance dari registry yang mungkin foldernya sudah hilang
if [[ -f "$REGISTRY" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        rname="$(awk '{print $1}' <<< "$line")"
        [[ -z "$rname" ]] && continue
        found="no"
        for x in "${INSTANCES[@]:-}"; do [[ "$x" == "$rname" ]] && found="yes" && break; done
        [[ "$found" == "no" ]] && INSTANCES+=("$rname")
    done < "$REGISTRY"
fi

if [[ ${#INSTANCES[@]} -eq 0 ]]; then
    warn "Tidak ada instance GenieACS yang terdaftar."
    # Tetap lanjut untuk membersihkan service multi-proxy & orphan unit.
fi

# ── Tampilkan ringkasan ──────────────────────────────────────
echo ""
echo -e "${RED}${BOLD}  ⚠ BERSIHKAN SEMUA GENIEACS${NC}"
echo -e "  Folder root : $INSTANCES_DIR"
echo -e "  Instance    : ${#INSTANCES[@]}"
for n in "${INSTANCES[@]:-}"; do
    [[ -z "$n" ]] && continue
    echo -e "    - ${CYAN}$n${NC}  (DB: genieacs_${n})"
done
if [[ "$KEEP_DB" == "yes" ]]; then
    echo -e "  Database    : ${YELLOW}DIPERTAHANKAN (--keep-db)${NC}"
else
    echo -e "  Database    : ${RED}AKAN DIHAPUS PERMANEN${NC}"
fi
echo ""

# ── Konfirmasi ───────────────────────────────────────────────
if [[ "$ASSUME_YES" != "yes" ]]; then
    echo -e "${RED}  Tindakan ini TIDAK bisa dibatalkan.${NC}"
    read -rp "$(echo -e "${RED}Ketik 'HAPUS SEMUA' untuk konfirmasi: ${NC}")" CONFIRM
    [[ "$CONFIRM" != "HAPUS SEMUA" ]] && echo "Dibatalkan." && exit 0
fi

# ── Helper: drop database MongoDB ────────────────────────────
drop_mongo_db() {
    local db="$1"
    local cmd="db.getSiblingDB('${db}').dropDatabase()"
    if command -v mongosh &>/dev/null; then
        mongosh --quiet --eval "$cmd" &>/dev/null && return 0 || return 1
    elif command -v mongo &>/dev/null; then
        mongo --quiet --eval "$cmd" &>/dev/null && return 0 || return 1
    fi
    return 2
}

# ── Hapus tiap instance ──────────────────────────────────────
for USERNAME in "${INSTANCES[@]:-}"; do
    [[ -z "$USERNAME" ]] && continue
    INST_DIR="$INSTANCES_DIR/$USERNAME"
    DB_NAME="genieacs_${USERNAME}"

    info "Menghapus instance: ${USERNAME}"

    # Stop & disable services per instance
    for SVC in proxy ui nbi fs cwmp; do
        SVCNAME="genieacs-${USERNAME}-${SVC}"
        systemctl stop    "$SVCNAME" &>/dev/null || true
        systemctl disable "$SVCNAME" &>/dev/null || true
        rm -f "/etc/systemd/system/${SVCNAME}.service"
    done

    # Hapus database (kecuali --keep-db)
    if [[ "$KEEP_DB" == "yes" ]]; then
        warn "  DB $DB_NAME dipertahankan"
    else
        if drop_mongo_db "$DB_NAME"; then
            success "  DB $DB_NAME dihapus"
        else
            rc=$?
            if [[ $rc -eq 2 ]]; then
                warn "  mongosh/mongo tidak ada — hapus manual: use $DB_NAME → db.dropDatabase()"
            else
                warn "  Gagal hapus DB $DB_NAME (cek MongoDB)"
            fi
        fi
    fi

    # Hapus folder instance
    if [[ -d "$INST_DIR" ]]; then
        rm -rf "$INST_DIR"
        success "  Folder $INST_DIR dihapus"
    fi
done

# ── Hapus service multi-proxy ────────────────────────────────
info "Menghapus service genieacs-multi-proxy..."
systemctl stop    genieacs-multi-proxy &>/dev/null || true
systemctl disable genieacs-multi-proxy &>/dev/null || true
rm -f /etc/systemd/system/genieacs-multi-proxy.service

# ── Bersihkan orphan unit genieacs-*-{cwmp,fs,nbi,ui,proxy} ──
info "Membersihkan sisa unit file genieacs-*..."
for UNIT_FILE in /etc/systemd/system/genieacs-*.service; do
    [[ -e "$UNIT_FILE" ]] || continue
    UNIT_NAME="$(basename "$UNIT_FILE" .service)"
    systemctl stop    "$UNIT_NAME" &>/dev/null || true
    systemctl disable "$UNIT_NAME" &>/dev/null || true
    rm -f "$UNIT_FILE"
done

systemctl daemon-reload
systemctl reset-failed &>/dev/null || true
success "Semua service genieacs dihapus"

# ── Hapus registry & folder root jika kosong ─────────────────
rm -f "$REGISTRY"
if [[ -d "$INSTANCES_DIR" ]] && [[ -z "$(ls -A "$INSTANCES_DIR" 2>/dev/null)" ]]; then
    rmdir "$INSTANCES_DIR" 2>/dev/null || true
    success "Folder root $INSTANCES_DIR dihapus (kosong)"
else
    success "Registry dihapus"
fi

echo ""
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}   Semua GenieACS berhasil dibersihkan${NC}"
if [[ "$KEEP_DB" == "yes" ]]; then
    echo -e "${YELLOW}   Catatan: database MongoDB dipertahankan (--keep-db)${NC}"
fi
echo -e "${GREEN}${BOLD}============================================================${NC}"
echo -e "  Cek sisa service : ${YELLOW}systemctl list-units 'genieacs-*'${NC}"
echo -e "  Cek sisa DB      : ${YELLOW}mongosh --eval \"db.adminCommand('listDatabases')\"${NC}"
echo "============================================================"
