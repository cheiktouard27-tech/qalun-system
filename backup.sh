#!/usr/bin/env bash
# نسخة احتياطية من قاعدة بيانات معهد قالون
set -euo pipefail
cd "$(dirname "$0")"
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p backups
python - <<PY
import sqlite3
src=sqlite3.connect('data/qalun.sqlite3')
dst=sqlite3.connect('backups/qalun-${STAMP}.sqlite3')
with dst: src.backup(dst)
PY
# أبقِ على آخر 14 نسخة فقط
ls -1t backups/*.sqlite3 2>/dev/null | tail -n +15 | xargs -r rm --
echo "Backup complete"
