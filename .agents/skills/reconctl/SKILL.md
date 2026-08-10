---
name: reconctl
description: >-
  Refresh and audit the reconctl-backed attack-surface target inventory. Use when
  asked to discover internet-facing hosts, classify unclassified targets, maintain
  curated target metadata, or deactivate retired hosts. Use reconctl for every
  inventory read and write; never runs a vulnerability scan and never commits.
---

# reconctl

Maintain the PostgreSQL-backed target inventory through `reconctl`. Each immutable hostname is classified as `public`, `prod`, `non-prod`, `internal`, `unclassified`, or `deactivated`. Curated fields belong to operators; `observed`, `network`, `http`, `tech`, `tls`, and `scan` belong to discovery and scanning runtimes.

## Boundaries

- Use `reconctl`, never direct SQL or edits to legacy `inventory/*.json` and `.gen/` files.
- Determine which database existing runtime configuration selects without printing its DSN. Entity commands automatically apply migrations; get explicit approval before touching a production database or real production data.
- Discovery writes run history, refreshes machine-owned observations, and creates new identities as `unclassified` with the `safe` profile. Present proposed classifications and reasons before changing those curated defaults.
- Never run `reconctl scan`, never edit machine-owned fields, and never commit.
- Treat `reconctl target update` as a full replacement of the curated projection. Read the target first and carry forward every unchanged curated field: `class`, `app`, `cluster`, `source`, `profiles`, `ports`, `tags`, `notes`, and `reason`.

## Procedure

1. Verify the installed CLI and discovery engines:

```bash
reconctl --help
reconctl engine list --kind discovery --json
```

If a required engine is not installed, report the reduced discovery coverage. Do not install or silently omit an engine unless installation is part of the request.

2. Inspect the configured zones, recent discovery history, and current unclassified queue:

```bash
reconctl zone list --json
reconctl discover list --limit 10 --json
reconctl target list --class unclassified --json
```

Keep the same `RECON_DB_URL`, `--db-url`, or local embedded database selection for every command in the workflow.

3. Run the smallest discovery that matches the request. With no selector or explicit input, discovery enumerates the configured zones. Explicit hosts, domains, and CIDRs may be combined, but cannot be combined with inventory filters.

```bash
reconctl discover --json
reconctl discover --domain example.com --profile default --json
reconctl discover --host api.example.com --profile default --json
reconctl discover --selector 'env=prod,tier in (frontend,api)' --json
```

Stop and report the run error if discovery fails. Do not continue with classifications based on a partial result.

4. Triage each `unclassified` host:
   - inspect it with `reconctl target get <host> --json`;
   - inspect the completed discovery with `reconctl discover get <run-id> --json` to see which engines observed it;
   - search the authoritative infrastructure configuration for ownership and record the source path;
   - classify non-production clusters and beta/demo hosts as `non-prod`;
   - classify production apps and control-plane endpoints as `prod`;
   - classify private endpoints as `internal` and explain the intended reachability;
   - classify marketing, documentation, and third-party origins as `public`, with only the `safe` profile for third-party origins;
   - propose the curated `app`, `cluster`, `source`, `profiles`, `ports`, `tags`, and `notes` fields.

5. Triage known hosts absent from the latest completed full discovery. Confirm current HTTP reachability with `reconctl ping <host> --json` and verify retirement from authoritative infrastructure configuration. Propose `class=deactivated` only with an explicit `reason`; absence from one run is not enough. Call out dangling-CNAME takeover risk without running a vulnerability scan.

6. Present a per-host curated-field diff with a one-line classification justification. After confirmation, update through `reconctl`, supplying the complete curated projection copied from the preceding `target get` output. Use comma-separated values for list fields:

```bash
reconctl target update api.example.com class=prod app=api cluster=prod source=path/to/config profiles=safe ports=443 tags=api,prod notes='Production API' --json
```

For a deactivated target, include `reason=<why it was retired>` and retain every other curated field that should survive. Omit `reason` for every other class.

7. Verify every changed host and the remaining queue:

```bash
reconctl target get api.example.com --json
reconctl target list --class unclassified --json
```

## Reference

- CLI and database selection: `internal/cli/root.go`
- Entity operations: `internal/entities/entities.go`
- Discovery and scan targeting: `internal/entities/actions.go`, `internal/entities/targeting.go`
- Target contract: `internal/api/target.go`, `internal/schema/target.schema.json`
