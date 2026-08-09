# Nuclei security scanning

Outside-in vulnerability scanning of the Flanksource internet-facing surface with
[Nuclei](https://github.com/projectdiscovery/nuclei). This complements the inside-out
hardening already in the repo (VPC flow logs, Data Access audit logs, client-IP
capture in `clickhouse/schema/`) by continuously checking what an unauthenticated
attacker actually sees.

Scans are **run locally on demand** — there is no CI wiring and nothing is deployed
into the clusters. Everything is orchestrated through `Taskfile.yaml`; the repo-root
`Makefile` exposes thin `make nuclei-*` wrappers.

## Layout

```
nuclei/
  inventory/
    inventory.json          versioned manifest and discovery zones
    inventory.schema.json   Draft 2020-12 manifest schema
    target.schema.json      Draft 2020-12 target schema
    targets/<fqdn>.json     one canonical document per target
  config/
    safe.yaml               non-intrusive profile (prod-safe)
    full.yaml               DAST/fuzzing profile (gated)
    discovery.naabu.yaml    bounded port-discovery profile
    discovery.httpx.yaml    HTTP metadata and login discovery profile
    discovery-paths.txt     safe paths checked on live HTTP origins
    nuclei-ignore           extra tag/id excludes
  templates/
    baseline/               our own TLS + header + cookie + redirect standard
    cloud/                  GCP/AWS metadata SSRF, public buckets, exposed k8s/kubelet
    apps/                   mission-control, kratos, tenant-controller, otel, caddy, argocd, flux, httpbin
    workflows/              flanksource-baseline.yaml
  hack/                     discovery and report helpers
  app/                      Vite + clicky-ui inventory admin UI
  .claude/skills/           nuclei-targets inventory maintenance skill
  results/                  scan output (gitignored)
  .gen/                     rendered target lists (gitignored)
```

## Quick start

```bash
make nuclei-tools                 # preflight: which tools are present/missing
task -d nuclei tools:install      # go install subfinder/httpx/dnsx/naabu (optional)
task -d nuclei inventory:validate # validate the canonical JSON inventory
make nuclei-validate              # validate all custom templates
make nuclei-scan                  # SAFE scan of non-prod + public (default group)
make nuclei-report                # markdown summary of the latest result
```

Or drive the Taskfile directly from this directory:

```bash
task                              # list all tasks
task scan:safe GROUP=non-prod
task scan:tls GROUP=public
task scan:takeover                # dangling-CNAME check across all + deactivated hosts
task targets:discover             # refresh discovery + drift report
task app:dev                      # admin UI: tag/bulk-edit targets, see observed state
```

## Admin app

`task app:dev` (or `make nuclei-app`) opens a local Vite + clicky-ui UI at
`localhost:5280` with three tabs:

- **Inventory** — filter and bulk-edit targets, or open `/inventory/:host` for a
  preview-first detail page. Edit mode is driven by `target.schema.json`; host identity
  and machine-owned observation fields remain read-only. **Discover subdomains** runs
  NS/MX resolution, subfinder, Naabu, and httpx and lets you classify unknown hosts before adding them.
- **Scans** — browse every `results/*.jsonl` run (severity breakdown per run) and drill
  into its findings, grouped by result type with the affected domains on each group
  header (regroup by severity/domain/none); expand a finding for remediation, references,
  reproduce-curl and the raw request.
- **Profiles** — edit the tracked Nuclei, Naabu, and httpx discovery profiles
  through a clicky-ui JSON Schema form backed by the upstream CLI options. Saves are
  type-checked and written directly to `config/*.yaml`.

See [app/README.md](app/README.md).

## Tags & observed state

Every target carries free-form `tags` used for filtering and bulk selection. Its single
JSON document contains both curated definition fields and machine-owned `observed`,
`network`, `http`, `tech`, `tls`, and `scan` sections. Discovery updates successful
observations for known targets while leaving unknown discoveries unclassified; clean
scans update `last_scan` and `last_findings` in the same document.

## Target classes

| Class         | Meaning                                                    | In default scan |
|---------------|------------------------------------------------------------|:---------------:|
| `public`      | Marketing/docs; some proxy to third parties (Webflow)      | yes             |
| `prod`        | Production app + control-plane endpoints                   | no (opt-in)     |
| `non-prod`    | Beta/demo/sandbox                                          | yes             |
| `internal`    | Private GKE endpoints — reachable only over Tailscale      | no              |
| `deactivated` | Retired but kept for subdomain-takeover coverage           | takeover only   |

`inventory/targets/*.json` is the single source of truth. `task targets:render` validates
every document and expands the inventory into
`.gen/<class>.txt` (and `.gen/<class>.<profile>.txt`) lists for `nuclei -l`. Never
hand-edit `.gen/` — regenerate it.

## Profiles

- **safe** (`config/safe.yaml`) — `dns,ssl,tcp,http`, severity `low`+, rate-limited to
  50 req/s, **no fuzzing, no DAST, no brute-force, no DoS**. Safe against production.
- **full** (`config/full.yaml`) — adds `-dast` fuzzing (SQLi/XSS/SSTI/traversal) and
  default-credential checks. **Sends malicious payloads.** `task scan:full` refuses any
  group containing `prod`/`public` unless `CONFIRM=yes`.

The DAST payloads come from the **community templates** (`-t dast/`, resolved against the
`nuclei-templates` checkout), which `templates/` does not carry — `task templates:update`
installs them and `task tools:check` reports them missing. `task scan:full` loads both
roots: `templates/` (custom) + `dast/` (community). Everything the `type`/`severity`
filters in `config/full.yaml` reject is dropped, so `headless` DAST templates never run.

The **discovery** profile combines `config/discovery.naabu.yaml` and
`config/discovery.httpx.yaml`. Naabu performs a bounded top-100 CONNECT scan and limits
CDN/WAF addresses to ports 80 and 443. httpx probes the resulting endpoints plus the
safe paths in `config/discovery-paths.txt`, collecting status, response time, response
headers, and application metadata. The discovery runner still owns its input files and
machine-readable JSON output flags.

Every scan sends `User-Agent: flanksource-security-scan/nuclei` and
`X-Flanksource-Scan`, so its requests are attributable in `telemetry.nginx_access_logs`
(the `client_ip` column added in `clickhouse/schema/001-nginx-access-logs-client-ip.sql`).

## Safety notes

- `internal` hosts are private GKE endpoints. Scanning them is only meaningful **from
  outside the tailnet** (to confirm they stay private) — a hit on `k8s-api-anonymous`
  from a machine already on Tailscale is expected, not a finding.
- `flanksource.com` / `www.` proxy to a third-party Webflow origin — they carry
  `profiles: [safe]` only and must never be fuzzed.
- Results land in `results/` and are gitignored — they describe live infrastructure
  and must not be committed.

## Maintaining the target list

Run `task targets:discover` (or use the **nuclei-targets** skill). It
unions static scrape of `../specs`, NS/MX targets and `subfinder` results over the DNS
zones, and `kubectl get ingress` across reachable contexts — scans in-domain candidates
with Naabu, probes open HTTP endpoints and known login paths with httpx, updates typed
observations for known targets, and reports unknown drift. Unknown hosts
are never added automatically; classification remains a human decision.
