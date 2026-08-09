---
name: nuclei-targets
description: >-
  Refresh and audit the JSON-backed Nuclei target inventory for the azure-production
  repo. Use when asked to discover internet-facing hosts, classify new targets, or
  deactivate retired hosts. Never runs a scan and never commits.
---

# nuclei-targets

Maintain `nuclei/inventory/targets/*.json`, the source of truth for what Nuclei scans hit. Each immutable hostname has one Draft 2020-12 validated document and is classified as `public`, `prod`, `non-prod`, `internal`, or `deactivated`.

## Boundaries

- Present classifications and reasons before applying them. Unknown discoveries are never added automatically.
- Never run a vulnerability scan and never commit.
- Never edit `.gen/`; `task targets:render` owns generated lists.
- Never edit the machine-owned `observed`, `network`, `http`, `tech`, `tls`, or `scan` sections by hand.

## Procedure

1. From `nuclei/`, run `task tools:check`. If `subfinder` or `httpx` is missing, report the reduced discovery coverage instead of pretending the result is complete.

2. Run `task targets:discover`. It writes `.gen/discovered-hosts.txt` and `.gen/discovered.json`, updates typed observations for known targets, and exits 3 when drift exists. Its sources are:
   - static `rg` searches over `../specs` for ingress hosts and certificate DNS names;
   - `subfinder` over the zones in `inventory/inventory.json`;
   - Cloud DNS records when gcloud is authenticated;
   - ingress resources across reachable Kubernetes contexts;
   - httpx response, network, technology, ASN, CPE, and TLS certificate probes.

3. Triage each unknown host from the drift report:
   - inspect its `.gen/discovered.json` record;
   - search `../specs` for ownership and record the source path;
   - classify non-production clusters and beta/demo hosts as `non-prod`;
   - classify production apps and control-plane endpoints as `prod`;
   - classify private endpoints as `internal` and explain the intended reachability;
   - classify marketing, documentation, and third-party origins as `public`, with only the `safe` profile for third-party origins;
   - propose the curated `app`, `cluster`, `source`, `profiles`, `ports`, `tags`, and `notes` fields.

4. Triage known hosts absent from discovery. Confirm DNS and HTTP state. Propose `class: deactivated` only with an explicit `reason`. Call out dangling-CNAME takeover risk and recommend the separate `task scan:takeover` check when appropriate.

5. Present a per-host JSON diff with a one-line classification justification. After confirmation, update or create only `inventory/targets/<host>.json`, then run:

```bash
task inventory:validate
task targets:render
```

## Reference

- Manifest and zones: `nuclei/inventory/inventory.json`
- Manifest schema: `nuclei/inventory/inventory.schema.json`
- Target schema: `nuclei/inventory/target.schema.json`
- Discovery logic: `nuclei/hack/discover-targets.sh`
