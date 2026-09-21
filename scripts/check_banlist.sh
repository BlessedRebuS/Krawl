#!/bin/sh
# Valida banlist.txt: non vuota, abbastanza righe, solo IP/CIDR (v4 o v6).
set -eu
FILE="${1:-banlist.txt}"
MIN_LINES="${MIN_LINES:-10}"

[ -s "$FILE" ] || { echo "Error: $FILE missing or empty"; exit 1; }

lines=$(grep -cve '^[[:space:]]*$' "$FILE" || true)
if [ "$lines" -lt "$MIN_LINES" ]; then
  echo "Error: $FILE too small ($lines lines, min $MIN_LINES)"
  exit 1
fi

if grep -ve '^[[:space:]]*$' "$FILE" | grep -nve '^[0-9a-fA-F:.]\+\(/[0-9]\+\)\?[[:space:]]*$' ; then
  echo "Error: $FILE contains non-IP lines (shown above)"
  exit 1
fi

echo "OK: $FILE, $lines entries"
