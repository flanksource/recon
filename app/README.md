# Nuclei Inventory admin app

A local Vite + React application built on `@flanksource/clicky-ui` for maintaining the canonical JSON target inventory, inspecting observed network and TLS metadata, running scans, and editing scanner profiles.

The application has no authentication and is intended for local development only. The Vite middleware supplies the filesystem-backed API in both development and preview mode.

## Run

```bash
task -d nuclei app:install
task -d nuclei app:dev
```

Open `http://localhost:5280`. From the repository root, `make nuclei-app` starts the same process.

## Routes

- `/` redirects to `/inventory`.
- `/inventory` lists all targets with filters, bulk editing, discovery, and scan controls. It shows HTTP status and response time, Naabu-discovered ports, known paths, and detected login methods. Selected targets can be rescanned with the combined Naabu and httpx discovery profile alongside the Nuclei profiles.
- `/inventory/:host` opens a preview-first target detail page with **Rescan discovery** and **Run Nuclei scan** actions. Nuclei runs start from a tracked profile, expose schema-driven run-only tweaks, and leave the saved profile unchanged. Edit mode uses the Draft 2020-12 target schema; host identity and all machine-owned sections are hidden from the editor.
- `/scans` lists persisted scan runs. `/scans?file=<result>` deep-links a result.
- `/profiles` edits the tracked Nuclei, Naabu, and httpx YAML profiles through their generated schemas.

Navigation uses the browser History API, so target details and scan results can be bookmarked and reloaded directly.

## Inventory contract

`nuclei/inventory/` is the only inventory source:

```text
inventory/
  inventory.json          manifest and discovery zones
  inventory.schema.json   manifest schema
  target.schema.json      target schema
  targets/<fqdn>.json     one document per immutable host
```

The editable definition fields are `class`, `app`, `cluster`, `source`, `profiles`, `ports`, `tags`, `notes`, and `reason`. The `observed`, `network`, `http`, `tech`, `tls`, and `scan` sections are machine-owned and read-only in the UI. Deactivated targets require a reason; reactivation removes it.

All writes are per-host and atomic. A bulk save calls the same target endpoint once per changed row and reports partial progress if a later target fails.

## API

| Method            | Path                           | Purpose                                                         |
| ----------------- | ------------------------------ | --------------------------------------------------------------- |
| `GET`             | `/api/inventory`               | Validated manifest, targets, and tag vocabulary                 |
| `GET`             | `/api/inventory/schema/target` | Target JSON Schema used by the editor                           |
| `GET`             | `/api/inventory/:host`         | One validated target document                                   |
| `PUT`             | `/api/inventory/:host`         | Replace editable fields while preserving machine fields         |
| `GET`             | `/api/discover`                | Cached classified/unclassified discovery view                   |
| `POST`            | `/api/discover`                | Run discovery, update known observations, and refresh the cache |
| `GET`             | `/api/scans`                   | List scan result files                                          |
| `GET`             | `/api/scans/:file`             | Read findings from one result                                   |
| `GET/POST/DELETE` | `/api/scan`                    | Read, start, or cancel the active scan                          |
| `GET`             | `/api/scan/events`             | Stream scan status and stdout/stderr over SSE                   |
| `GET`             | `/api/profiles`                | List validated scanner profiles                                 |
| `PUT`             | `/api/profiles/:engine/:name`  | Update one validated profile                                    |

The static `vite build` output has no standalone backend. Serve it with `vite preview` when filesystem persistence is required.

## Discovery and scans

Discovery unions the static specification scrape, NS and MX targets from each configured zone, passive subdomain enumeration, and optional cluster enumeration. It runs the bounded `config/discovery.naabu.yaml` port profile, feeds discovered host/port endpoints to `config/discovery.httpx.yaml`, and checks the safe paths in `config/discovery-paths.txt`. Successful observations replace the typed machine snapshot for known targets, including open ports, HTTP status and response time, known paths, and authentication methods derived from `WWW-Authenticate` challenges and login/OAuth/OIDC routes. Failed probes record the attempt and error without erasing the last successful snapshot. Unknown hosts remain in the discovery cache until a user classifies and saves them.

The scan dialog runs the same combined discovery runner over selected inventory targets. This targeted rescan is available from bulk selection and the target detail view; it refreshes machine-owned observations without creating a Nuclei findings result.

The target detail scan can use any tracked Nuclei profile as its defaults. Its effective configuration is validated against the same profile schema, written under `.gen/` only while Nuclei is running, and removed when the process exits. DAST settings retain the production/public authorization gate even when they were enabled as a run-only tweak.

Both UI and Taskfile Nuclei scans use the shared inventory store. A clean Nuclei run records `last_scan` and per-host finding counts; failed or cancelled scans do not claim success. Full DAST scans against production, public, or unclassified hosts require explicit confirmation.

The scan dialog receives process updates from `/api/scan/events`, labels stdout, stderr, and runner messages separately, and retains a bounded output tail alongside the structured request, template, finding, timing, exit, and discovery-observation summary.

## Validation

```bash
task -d nuclei inventory:validate
task -d nuclei app:test
task -d nuclei app:lint
task -d nuclei app:build
```

`server/inventory-store.ts` is the shared Ajv-backed persistence seam used by the API and the operational CLI. `server/inventory-cli.ts` validates, renders target lists, merges discovery observations, and records scan results.
