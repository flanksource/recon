#!/usr/bin/env bash
# Summarise the most recent (or a named) JSONL nuclei result into grouped markdown.
# Usage: report.sh [results/<file>.jsonl]
set -euo pipefail

cd "$(dirname "$0")/.."

jsonl="${1:-$(ls -t results/*.jsonl 2>/dev/null | head -1 || true)}"
if [ -z "${jsonl}" ] || [ ! -s "${jsonl}" ]; then
  echo "No JSONL results found in results/. Run a scan first (task scan:safe)." >&2
  exit 1
fi

md="${jsonl%.jsonl}.md"
total=$(wc -l <"${jsonl}" | tr -d ' ')

{
  echo "# Nuclei scan report"
  echo
  echo "- Source: \`${jsonl}\`"
  echo "- Findings: ${total}"
  echo
  echo "## By severity"
  echo
  echo "| Severity | Count |"
  echo "|---|---|"
  jq -r '.info.severity' "${jsonl}" | sort | uniq -c \
    | awk '{printf "| %s | %s |\n", $2, $1}'
  echo
  echo "## Findings"
  echo
  echo "| Severity | Template | Host | Matched |"
  echo "|---|---|---|---|"
  jq -r '[.info.severity, .["template-id"], (.host // .url), (.["matched-at"] // .url)] | @tsv' "${jsonl}" \
    | sort \
    | awk -F'\t' '{printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4}'
} >"${md}"

echo "Wrote ${md}"
cat "${md}"
