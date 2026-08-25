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
- `/resources` lists every resource the scans examined, whatever the verdict — including the ones every check passed on, which is what makes a clean resource distinguishable from one nobody looked at. Paged against the server rather than loaded whole: resources are enumerated by a machine and bounded by nothing. Filters cover provider, account, type, service, region, engine, tags, labels, kind, severity, state, and a three-way `status` of failing / clean / unchecked. **Sync insights** previews and then syncs current states for the exact filtered resource set.
- `/resources/:id` opens one resource: its identity (including the `configType` and `externalIds` a Mission Control lookup would use), a compliance roll-up read from the `compliance:` tags the checks carry, and every finding currently open against it, each expanding to the same detail — and the same mute menu — the scan results use.
- `/scans` lists persisted scan runs. `/scans?file=<result>` deep-links a result.
- `/findings` groups current states by engine and check, defaulting to open and manual-review states. Resolved and muted toggles add lifecycle states, each group expands to its paged affected resources, and **Sync insights** uses the exact active selection.
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
| `GET/POST`        | `/api/v1/discover`             | List discovery history or run domain/host/CIDR discovery        |
| `GET/POST`        | `/api/v1/scan`                 | List scan history or discover then start a scan                  |
| `GET`             | `/api/v1/finding`              | Query findings across persisted scans; `?resource=` drills down |
| `GET`             | `/api/v1/finding-group`        | Page current states grouped by engine and check                  |
| `GET`             | `/api/v1/finding-state`        | Page current resource/check states                               |
| `POST`            | `/api/v1/finding/sync`         | Preview or sync selected current finding states                  |
| `GET`             | `/api/v1/resource`             | Page the estate — answers `{data, page:{limit,offset,total}}`    |
| `GET`             | `/api/v1/resource/:id`         | One resource by ulid or `provider/account/uid`                  |
| `POST`            | `/api/v1/resource/sync`        | Preview or sync states for selected resources                    |
| `GET`             | `/api/scan/current`            | Read the current or most recent scan status                      |
| `POST`            | `/api/scan/cancel`             | Cancel the active scan                                           |
| `GET`             | `/api/scan/events`             | Stream scan status and stdout/stderr over SSE                   |
| `GET`             | `/api/profiles`                | List validated scanner profiles                                 |
| `PUT`             | `/api/profiles/:engine/:name`  | Update one validated profile                                    |

The static `vite build` output has no standalone backend. Serve it with `vite preview` when filesystem persistence is required.

## Discovery and scans

Discovery accepts domains, hosts, CIDRs, or a Kubernetes label selector over inventory tags. It runs each participating engine with the requested discovery profile, probes the union of explicit and enumerated identities, and stores new identities as `unclassified` with `profiles: [safe]`. Successful observations replace the typed machine snapshot while preserving curated fields. Failed probes record the attempt and error without erasing the last successful snapshot.

The scan dialog calls the root scan resource over selected inventory targets. The server completes discovery first, refreshes machine-owned observations, and only then starts Nuclei; a discovery failure stops the scan.

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
