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
  .agents/skills/           reconctl inventory maintenance skill
  results/                  retained scan artifacts (gitignored)
    <engine>/<date>/<run>/  targets.txt, findings.jsonl, config.json,
                            scan.json, output.log, mutes.json
  .gen/                     rendered target lists (gitignored)
```

Every run keeps its own directory under `results/`, partitioned by engine and by
the day it started. The directory holds the endpoint list the selector resolved
to, the engine's own output in the engine's own format, the effective
configuration (the profile with the run's overrides already applied), the run's
terminal record, and the engine log. Each run records the path, and the Scans
tab links to every file in it.

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
`localhost:5280` with these tabs:

- **Inventory** — filter and bulk-edit targets by kind and class, or open `/inventory/:host` for a
  preview-first detail page. Edit mode is driven by `target.schema.json`; host identity
  and machine-owned observation fields remain read-only. **Discover targets** runs
  NS/MX resolution, subfinder, Naabu, and httpx. Newly observed identities are added as
  `unclassified` with the `safe` profile so they are visible immediately without losing
  any curated fields on targets that already exist.
- **Scans** — browse every run (severity breakdown per run) and drill into its
  findings, grouped by result type with the affected domains on each group header
  (regroup by severity/domain/none); expand a finding for remediation, references,
  reproduce-curl and the raw request. The **Execution** tab adds what the run put on
  the wire — requests, responses, bytes, and breakdowns by status code, protocol,
  error kind and detected WAF — alongside the retained artifact directory, with a
  link to every file in it.
- **Profiles** — edit the tracked Nuclei, Naabu, and httpx discovery profiles
  through a clicky-ui JSON Schema form backed by the upstream CLI options. Saves are
  type-checked and written directly to `config/*.yaml`.
- **Mutes** — the findings that have been accepted, and what each rule covers. The
  form refuses a rule that would match everything, and **What would this hide?**
  reports what a rule would have removed from runs that already finished — which is
  the only way to see its reach, because a muted finding is never recorded. See
  [Muting findings](#muting-findings).

See [app/README.md](app/README.md).

## Tags & observed state

Every target carries free-form `tags` used for filtering and bulk selection. Its single
JSON document contains both curated definition fields and machine-owned `observed`,
`network`, `http`, `tech`, `tls`, and `scan` sections. Discovery updates successful
observations and creates conservative `unclassified` records for new targets; clean
scans update `last_scan` and `last_findings` in the same document.

## Compliance benchmarks

Alongside the outside-in scanning, recon runs **CIS benchmarks against cloud
accounts** with [CINC Auditor](https://cinc.sh/start/auditor/) — the
license-free build of Chef InSpec. Where nuclei asks what an unauthenticated
attacker can see, this asks whether the account behind it is configured
correctly, by reading the provider's own APIs with credentials.

```bash
reconctl engine install inspec           # installs system-wide; prompts for sudo
reconctl target create host=my-project kind=gcp-project class=prod profiles=gcp-cis
reconctl scan --engine inspec --host my-project
```

A cloud account is an inventory target like any other — classified, tagged and
filterable — but with `kind: gcp-project` rather than `host`. It has no address
and no ports, so discovery, liveness probes and endpoint-driven scans skip it;
`reconctl target list --kind gcp-project` lists them.

Findings land in the same table as everything else. Only failed and errored
controls become findings: a benchmark produces a few hundred results of which
most pass, and recording those would bury the ones worth acting on. The complete
report is retained per account as `inspec-<project>.json` in the run's artifact
directory, passes included.

The `gcp-cis` profile pins the
[GCP CIS 4.0 benchmark](https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark)
to a commit — its releases are years behind its default branch, so a tag would
pin a benchmark four major versions out of date. Authentication is Application
Default Credentials (`gcloud auth application-default login`); recon passes the
project id and never handles the credentials itself.

`cinc-auditor` installs system-wide to `/opt/cinc-auditor` and needs sudo. That
is inherent to the package rather than a choice: an omnibus build links that
prefix into its interpreter's dylib paths and its `$LOAD_PATH`, so a copy
unpacked into `.bin/` cannot run.

### Prowler source and CLI

Prowler's provider, compliance and check metadata is pinned as a shallow Git submodule at `third_party/prowler`. Initialize it after cloning recon:

```bash
git submodule update --init --depth 1 third_party/prowler
```

The matching CLI is Prowler 5.40.0 built from the same upstream commit. Install it as a PATH-managed application with a Python 3.10–3.13 interpreter:

```bash
pipx install "git+https://github.com/prowler-cloud/prowler.git@ba564af4f46fd7c4908d34798687eda36b88398c"
prowler --version
```

If Prowler is already installed, replace it with the pinned build:

```bash
pipx install --force "git+https://github.com/prowler-cloud/prowler.git@ba564af4f46fd7c4908d34798687eda36b88398c"
```

When updating Prowler, move the submodule gitlink and PATH install specification to the same reviewed commit, then regenerate and verify the derived catalogue. The upstream version, gitlink and generated catalogue must stay in sync.

## Target classes

| Class         | Meaning                                                    | In default scan |
|---------------|------------------------------------------------------------|:---------------:|
| `public`      | Marketing/docs; some proxy to third parties (Webflow)      | yes             |
| `prod`        | Production app + control-plane endpoints                   | no (opt-in)     |
| `non-prod`    | Beta/demo/sandbox                                          | yes             |
| `internal`    | Private GKE endpoints — reachable only over Tailscale      | no              |
| `unclassified`| Newly discovered identity awaiting review                  | safe only       |
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

## Muting findings

A **mute rule** records a finding nobody intends to act on. Rules are stored in the
database and edited on the **Mutes** tab, on the CLI, or over the API:

```bash
reconctl mute create name=accepted-open-redirect templates=open-redirect engines=nuclei \
    comment='httpbin is a deliberate fixture'
reconctl mute list
reconctl mute preview accepted-open-redirect
```

A rule selects on any combination of `templates` (the check), `resources` (the thing
the evidence names), `tags`, `severity`, and a `targets` selector over the inventory.
The rows are ANDed and the values within a row are ORed; a row left empty is not part
of the rule. `engines` says which engines the rule is considered for and selects no
finding on its own, so a rule carrying only an engine is refused — as is a rule that
selects nothing at all, because that would mute everything.

`expr` narrows the rows above with a [CEL](https://github.com/google/cel-spec)
expression over a single `finding` variable, holding the finding exactly as the API
renders it. It is what reaches detail the columns cannot:

```bash
reconctl mute create name=logs-buckets templates=gcp/bucket_public \
    'expr=finding.raw.resources[0].uid.startsWith("logs-")'
```

> On the CLI an argument containing `==` is read as a query parameter, so escape it as
> `\=\=` — `'expr=finding.severity \=\= "high"'`. The API and the Mutes tab take the
> expression verbatim.

A rule has two effects. Where the engine can express the same exclusion natively the
**check is never run** — nuclei's `exclude-id`/`exclude-tags`/`exclude-severity`,
Prowler's `excluded-checks`, a generated `.trivyignore` for trivy. That only happens
when the rule names exactly one row and scopes no targets or resources: engine
exclusions are a union while a rule is an intersection, so approximating one would
suppress findings the rule does not cover. Everything else — every rule with an
expression, and every rule InSpec sees, since it has no exclusion mechanism — is
applied to the results instead.

**A muted finding is not recorded.** It is dropped before the run is written, so it
does not appear in the database, the counts, the report or a Mission Control upload.
The engine's own `findings.jsonl` still holds every line it produced, and
`results/<run>/mutes.json` says which rule removed which of those lines, so the
artifact directory still explains itself without Postgres. The runs list shows
`N muted` alongside the finding count, and `reconctl scan --no-mutes` runs with every
rule ignored.

Because muting drops rather than marks, `reconctl mute preview <name>` — and the
**What would this hide?** button — is the way to check a rule's reach before trusting
it. It reports what the rule would have taken out of runs that already finished.

## Safety notes

- `internal` hosts are private GKE endpoints. Scanning them is only meaningful **from
  outside the tailnet** (to confirm they stay private) — a hit on `k8s-api-anonymous`
  from a machine already on Tailscale is expected, not a finding.
- `flanksource.com` / `www.` proxy to a third-party Webflow origin — they carry
  `profiles: [safe]` only and must never be fuzzed.
- Results land in `results/` and are gitignored — they describe live infrastructure
  and must not be committed.

## Maintaining the target list

The generated CLI exposes execution and history on the same resources:

```bash
reconctl discover --domain flanksource.com --profile default
reconctl discover --host api.flanksource.com --cidr 192.0.2.0/24
reconctl discover --selector 'env=prod,tier in (frontend,api)'
reconctl discover list

reconctl scan --host api.flanksource.com --profile safe
reconctl scan --selector 'env=prod' --profile safe
reconctl scan --engine inspec --kind gcp-project
reconctl scan list
```

Explicit `--host`, `--domain`, and `--cidr` values can be combined, but cannot be
combined with `--selector` or the other inventory filters. `--profile` defaults to
whichever profile the chosen engine ships. With no input, discovery uses the
configured zones and scan targets the whole inventory.

A scan with an endpoint-driven engine completes discovery first and stops if
discovery fails. A compliance scan skips it: discovery resolves and probes
network addresses, and a cloud account has none — `--domain` and `--cidr` are
refused there for the same reason.

The API mirrors those commands: `POST /api/v1/discover` and `POST /api/v1/scan`
execute, while `GET /api/v1/discover` and `GET /api/v1/scan` list history. Request
bodies use the flag names, for example
`{"domain":["flanksource.com"],"profile":"default"}` or
`{"selector":"env=prod","profile":"safe"}`.

## Uploading findings to Mission Control

A finished run can be pushed to Mission Control, where each finding becomes an
**insight** (`config_analysis`) attached to the config item it is about:

```bash
faro auth login --server https://mission-control.example.com
reconctl scan upload <scan-id> --dry-run     # what would land, nothing written
reconctl scan upload <scan-id>
```

The credential is faro's — there is no server or token flag, and `--context`
picks between configured servers. The endpoint requires the `agent-push`
permission, which Mission Control grants to the `admin` and `agent` roles only;
`faro whoami` shows what the current context holds.

Each finding is resolved against the catalog rather than given a config item of
recon's own: the resource the engine named, then the host, then the target's
cluster and finally the target itself. A finding that only matches one of the
later rungs is **rolled up** — recorded against the cluster or account
containing it — and one that matches nothing is reported, not uploaded. An
insight attached to the wrong resource is worse than one that is missing and
accounted for, so `--dry-run` reports the same coverage a real upload would
achieve. `--severity` sets a floor and `--unresolved=error` refuses to push
anything unless every finding resolved.

Uploading twice does not duplicate: an insight's identity is derived from the
config, the analyzer and the location, so a re-scan updates the row it wrote
last time and its `first_observed` survives. The Scans tab exposes the same
operation as a button, and the API as `POST /api/v1/scan/{id}/upload`.
