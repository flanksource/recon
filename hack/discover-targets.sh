#!/usr/bin/env bash
# Discover live hostnames from static, DNS, and cluster sources, scan ports with Naabu,
# probe HTTP endpoints with httpx, and diff against
# the curated JSON inventory. Reports drift; never creates unclassified targets. Exits non-zero
# when drift is found so it can gate CI later.
#
#   static  : Ingress host: values + cert-manager dnsNames under ../specs
#   dns     : NS/MX queries + subfinder over every inventory zone (+ gcloud when authed)
#   cluster : kubectl get ingress -A across reachable kube-contexts
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "MISSING (required): rg — install ripgrep before running discovery." >&2
  exit 1
fi

cd "$(dirname "$0")/.."
mkdir -p .gen
repo_root="$(cd .. && pwd)"
raw=".gen/discovered-raw.txt"
: >"$raw"

echo "[*] static: scraping ${repo_root}/specs for Ingress hosts and cert dnsNames"
rg -oIN --no-heading 'host: *"?([a-z0-9*][a-z0-9.*-]*\.flanksource\.com)' -r '$1' \
  "${repo_root}/specs" 2>/dev/null >>"$raw" || true
rg -oIN --no-heading '([a-z0-9][a-z0-9.-]*\.flanksource\.com)' \
  "${repo_root}/specs" 2>/dev/null >>"$raw" || true

pnpm --dir app exec tsx server/inventory-cli.ts zones >.gen/_zones.txt
echo "[*] dns: resolving NS and MX targets"
pnpm --dir app exec tsx server/dns-discovery.ts --zones ../.gen/_zones.txt >>"$raw"

if command -v subfinder >/dev/null; then
  # One invocation over all zones (-dL) with a hard time cap, so an interactive
  # discovery from the app stays bounded even when a source is slow.
  echo "[*] dns: subfinder over $(wc -l <.gen/_zones.txt | tr -d ' ') zones (max ${SUBFINDER_MAX_TIME:-2}m)"
  subfinder -silent -dL .gen/_zones.txt \
    -timeout 10 -max-time "${SUBFINDER_MAX_TIME:-2}" 2>/dev/null >>"$raw" || true
else
  echo "[!] subfinder not installed — skipping passive DNS enumeration."
  echo "    install: task tools:install"
fi

# The gcloud + kubectl cluster enumeration needs GCP auth / VPN and can be slow or hang
# against private clusters. Set DISCOVER_NO_CLUSTER=1 (the admin app does) to skip it and
# rely on static scrape + NS/MX + subfinder + Naabu/httpx only.
if [ "${DISCOVER_NO_CLUSTER:-0}" = 1 ]; then
  echo "[*] cluster enumeration skipped (DISCOVER_NO_CLUSTER=1)"
else
  if command -v gcloud >/dev/null && gcloud auth print-access-token >/dev/null 2>&1; then
    echo "[*] dns: gcloud dns managed-zones"
    for mz in $(gcloud dns managed-zones list --format='value(name)' 2>/dev/null); do
      gcloud dns record-sets list --zone="$mz" --format='value(name)' 2>/dev/null \
        | sed 's/\.$//' >>"$raw" || true
    done
  else
    echo "[!] gcloud not authenticated — skipping Cloud DNS record enumeration."
  fi

  echo "[*] cluster: kubectl ingress across reachable contexts"
  if command -v kubectl >/dev/null; then
    for ctx in $(kubectl config get-contexts -o name 2>/dev/null); do
      kubectl --context="$ctx" --request-timeout=5s get ingress -A \
        -o jsonpath='{range .items[*]}{range .spec.rules[*]}{.host}{"\n"}{end}{end}' \
        2>/dev/null >>"$raw" || true
    done
  fi
fi

# Normalise: strip wildcards, lowercase, unique, keep only flanksource.com.
rg -oiN '[a-z0-9][a-z0-9.-]*\.flanksource\.com' "$raw" 2>/dev/null \
  | tr 'A-Z' 'a-z' | sort -u >.gen/discovered-hosts.txt || true
echo "[*] $(wc -l <.gen/discovered-hosts.txt | tr -d ' ') unique candidate hosts"

# Discover ports first, then probe every HTTP endpoint and known login path.
if [ -s .gen/discovered-hosts.txt ]; then
  if ! command -v naabu >/dev/null; then
    echo "MISSING (discovery): naabu — run 'task tools:install'" >&2
    exit 1
  fi
  if ! command -v httpx >/dev/null; then
    echo "MISSING (discovery): httpx — run 'task tools:install'" >&2
    exit 1
  fi
  pnpm --dir app exec tsx server/discovery-profile.ts \
    --hosts .gen/discovered-hosts.txt >.gen/discovered.json
  pnpm --dir app exec tsx server/inventory-cli.ts merge-discovery
fi

# Diff discovered vs known.
pnpm --dir app exec tsx server/inventory-cli.ts known >.gen/known-hosts.txt
new=$(comm -23 .gen/discovered-hosts.txt .gen/known-hosts.txt || true)
gone=$(comm -13 .gen/discovered-hosts.txt .gen/known-hosts.txt || true)

echo
echo "=== DRIFT REPORT ==="
if [ -n "$new" ]; then
  echo "NEW hosts discovered, not in inventory (classify with the reconctl skill):"
  echo "$new" | sed 's/^/  + /'
fi
if [ -n "$gone" ]; then
  echo "KNOWN hosts NOT seen by discovery (candidates for 'deactivated' / takeover risk):"
  echo "$gone" | sed 's/^/  - /'
fi
if [ -z "$new" ] && [ -z "$gone" ]; then
  echo "No drift. Inventory matches discovery."
  exit 0
fi
echo "==================="
exit 3
