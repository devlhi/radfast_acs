#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# fix-gettemp.sh — Perbaiki bug Virtual Parameter "gettemp" di SEMUA instance.
#
# Bug: fungsi linearRegression() memakai variabel _v3 tanpa deklarasi → sandbox
#      provision GenieACS (strict mode) melempar "ReferenceError: _v3 is not
#      defined", plus rumus regresi linear kurang tanda kurung (hasil suhu ngaco).
#
# Script ini menambal langsung dokumen gettemp di tiap database genieacs_<user>
# (hanya mengganti 2 substring; tidak menyentuh field lain). Idempotent: aman
# dijalankan berulang. Tidak mengubah virtual parameter lain.
#
# Jalankan di server (root): bash fix-gettemp.sh
# ---------------------------------------------------------------------------
set -euo pipefail

MONGO_HOST="${MONGO_HOST:-127.0.0.1:27017}"

# Pilih client mongo yang tersedia
if command -v mongosh >/dev/null 2>&1; then
    MONGO_CLIENT="mongosh"
elif command -v mongo >/dev/null 2>&1; then
    MONGO_CLIENT="mongo"
else
    echo "ERROR: 'mongosh' atau 'mongo' tidak ditemukan. Install mongodb client dulu." >&2
    exit 1
fi

echo "Memakai client: $MONGO_CLIENT @ $MONGO_HOST"

# Ambil daftar database genieacs_*
DBS=$("$MONGO_CLIENT" "mongodb://${MONGO_HOST}/admin" --quiet --eval '
  db.adminCommand({listDatabases:1}).databases
    .map(d => d.name)
    .filter(n => n.startsWith("genieacs_"))
    .join("\n");
' 2>/dev/null | grep -E '^genieacs_' || true)

if [[ -z "${DBS}" ]]; then
    echo "Tidak ada database genieacs_* ditemukan. Selesai."
    exit 0
fi

TOTAL=0
FIXED=0
for DB in ${DBS}; do
    TOTAL=$((TOTAL + 1))
    echo "→ ${DB}"
    RESULT=$("$MONGO_CLIENT" "mongodb://${MONGO_HOST}/${DB}" --quiet --eval '
      const vp = db.getCollection("virtualParameters").findOne({_id: "gettemp"});
      if (!vp || typeof vp.script !== "string") { print("SKIP: gettemp tidak ada"); quit(0); }
      let s = vp.script;
      const before = s;
      s = s.replace(
        "function linearRegression(_v1,_v2){_v3=_v1.length;",
        "function linearRegression(_v1,_v2){let _v3=_v1.length;"
      );
      s = s.replace(
        "const _v9=_v3*_v6-_v4*_v5/_v3*_v7-_v4*_v4,_v10=_v5-_v9*_v4/_v3;",
        "const _v9=(_v3*_v6-_v4*_v5)/(_v3*_v7-_v4*_v4),_v10=(_v5-_v9*_v4)/_v3;"
      );
      if (s === before) {
        if (s.includes("let _v3=_v1.length;")) print("OK: sudah diperbaiki sebelumnya");
        else print("WARN: pola tidak cocok (script mungkin sudah dimodifikasi)");
        quit(0);
      }
      db.getCollection("virtualParameters").updateOne({_id:"gettemp"}, {$set:{script:s}});
      print("FIXED");
    ' 2>/dev/null || echo "ERROR")
    echo "   ${RESULT}"
    [[ "${RESULT}" == *FIXED* ]] && FIXED=$((FIXED + 1)) || true
done

echo ""
echo "Selesai. ${FIXED}/${TOTAL} database diperbaiki."
echo "Catatan: GenieACS membaca virtual parameter dari cache. Restart service CWMP"
echo "agar perubahan langsung dipakai, mis: systemctl restart 'genieacs-*-cwmp'"
