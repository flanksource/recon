#!/usr/bin/env bash
# Capture the full response corpus of the TypeScript API before it is deleted.
#
# The output is the reference the Go port is verified against. It describes live
# infrastructure, so contract/golden/full/ is gitignored; only the curated
# contract/snapshot/ subset is committed.
#
# Usage: bash hack/capture-golden.sh [base-url]   (default http://localhost:5280)
set -euo pipefail

BASE="${1:-http://localhost:5280}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/contract/golden/full"

mkdir -p "$OUT/targets" "$OUT/scans"

fetch() {
  local path="$1" dest="$2"
  if ! curl -sS --fail-with-body "$BASE$path" | jq -S . > "$dest"; then
    echo "FAILED $path" >&2
    return 1
  fi
}

echo ">>> collections"
for p in inventory profiles scans discover scan; do
  fetch "/api/$p" "$OUT/$p.json"
  echo "    /api/$p"
done
fetch "/api/inventory/schema/target" "$OUT/target-schema.json"
echo "    /api/inventory/schema/target"

echo ">>> targets"
count=0
while read -r host; do
  fetch "/api/inventory/$host" "$OUT/targets/$host.json"
  count=$((count + 1))
done < <(jq -r '.rows[].host' "$OUT/inventory.json")
echo "    $count targets"

echo ">>> scan results"
count=0
while read -r file; do
  fetch "/api/scans/$file" "$OUT/scans/$file.json"
  count=$((count + 1))
done < <(jq -r '.scans[].file' "$OUT/scans.json")
echo "    $count results"

echo ">>> error shapes"
# A machine-owned field must be rejected as not editable (400).
curl -sS -X PUT -H 'content-type: application/json' \
  -d '{"class":"prod","profiles":["safe"],"tags":[],"http":{"status_code":500}}' \
  "$BASE/api/inventory/$(jq -r '.rows[0].host' "$OUT/inventory.json")" \
  | jq -S . > "$OUT/err-not-editable.json"
# A non-object run config must be rejected (400).
curl -sS -X POST -H 'content-type: application/json' \
  -d '{"hosts":["x.example.com"],"profile":"safe","config":[]}' \
  "$BASE/api/scan" | jq -S . > "$OUT/err-scan-config.json"
# An unknown target must 404 with the canonical message.
curl -sS "$BASE/api/inventory/no-such-host.example.com" | jq -S . > "$OUT/err-target-404.json"

echo ">>> SSE first frame"
curl -sN --max-time 2 "$BASE/api/scan/events" | head -c 2000 > "$OUT/scan-events.txt" || true

echo
echo "captured to $OUT"
find "$OUT" -type f | wc -l | xargs echo "files:"
