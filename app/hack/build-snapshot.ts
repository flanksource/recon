// Build contract/snapshot/ — the committed, self-contained corpus the Go
// contract suite imports and replays forever.
//
//   pnpm --dir app exec tsx hack/build-snapshot.ts
//
// It must survive the deletion of inventory/ and config/ in Phase 6, so it is a
// real (not symlinked) copy. Targets are real hosts — the full inventory is
// already tracked in git, so the subset adds no exposure. Scan findings are NOT:
// results/ is gitignored because it describes live vulnerabilities, so the
// snapshot's JSONL is synthesised from the real record *structure* with every
// host, IP, URL and payload replaced.
import { copyFileSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const NUCLEI_DIR = resolve(import.meta.dirname, "..", "..");
const SNAPSHOT = resolve(NUCLEI_DIR, "contract/snapshot");

type Target = Record<string, any>;
const inventory = JSON.parse(
  readFileSync(resolve(NUCLEI_DIR, "contract/golden/full/inventory.json"), "utf8"),
) as { version: number; zones: string[]; rows: Target[] };

const byHost = new Map(inventory.rows.map((row) => [row.host as string, row]));
const pick = (label: string, predicate: (t: Target) => boolean): Target => {
  const found = inventory.rows.find((t) => predicate(t) && !chosen.has(t.host));
  if (!found) throw new Error(`no unchosen target satisfies: ${label}`);
  chosen.add(found.host);
  reasons.push(`${found.host}  <- ${label}`);
  return found;
};
const chosen = new Set<string>();
const reasons: string[] = [];

// One per class, then one per machine-owned section that real data populates.
// Ordering matters: the most constrained predicates run first so a broad one
// (e.g. "class non-prod") cannot consume the only target that satisfies a
// narrow one.
pick("class deactivated + reason", (t) => t.class === "deactivated" && typeof t.reason === "string");
pick("full tls certificate", (t) => t.tls?.subject_cn !== undefined);
pick("tech.cpe entries", (t) => t.tech?.cpe !== undefined);
pick("network.cdn + network.asn", (t) => t.network?.cdn !== undefined && t.network?.asn !== undefined);
pick("curated ports + class internal", (t) => t.class === "internal" && Array.isArray(t.ports));
pick("failed observation (error, no http)", (t) => t.observed?.error !== undefined && t.http === undefined);
pick("scan.last_scan with findings", (t) => (t.scan?.last_findings ?? 0) > 0);
pick("profiles includes full", (t) => Array.isArray(t.profiles) && t.profiles.includes("full"));
pick("class prod", (t) => t.class === "prod");
pick("class public", (t) => t.class === "public");
pick("class non-prod with tags", (t) => t.class === "non-prod" && (t.tags?.length ?? 0) > 0);

const targets = [...chosen].sort().map((host) => byHost.get(host)!);

// Every class must appear, or the conditional `deactivated => reason` rule and
// the class-based scan gating go untested.
const classes = new Set(targets.map((t) => t.class));
for (const required of ["public", "prod", "non-prod", "internal", "deactivated"]) {
  if (!classes.has(required)) throw new Error(`snapshot is missing class ${required}`);
}

mkdirSync(resolve(SNAPSHOT, "inventory/targets"), { recursive: true });
mkdirSync(resolve(SNAPSHOT, "config"), { recursive: true });
mkdirSync(resolve(SNAPSHOT, "results"), { recursive: true });

for (const target of targets) {
  writeFileSync(
    resolve(SNAPSHOT, "inventory/targets", `${target.host}.json`),
    `${JSON.stringify(target, null, 2)}\n`,
  );
}
// The manifest and both schemas: the store validates against them on every read.
writeFileSync(
  resolve(SNAPSHOT, "inventory/inventory.json"),
  `${JSON.stringify({ $schema: "./inventory.schema.json", version: inventory.version, zones: inventory.zones }, null, 2)}\n`,
);
for (const schema of ["inventory.schema.json", "target.schema.json"]) {
  copyFileSync(resolve(NUCLEI_DIR, "inventory", schema), resolve(SNAPSHOT, "inventory", schema));
}

// Profiles, byte-for-byte — the leading comment blocks are load-bearing for the
// comment-preserving round-trip.
const configDir = resolve(NUCLEI_DIR, "config");
for (const name of readdirSync(configDir)) {
  copyFileSync(resolve(configDir, name), resolve(SNAPSHOT, "config", name));
}

// ---------------------------------------------------------------- findings
// Take the richest real result file for its structure, then replace every value
// that could identify live infrastructure or carry an exploit payload.
const source = "safe-non-prod-20260809-103049.jsonl";
const real = readFileSync(resolve(NUCLEI_DIR, "results", source), "utf8")
  .split("\n")
  .filter((line) => line.trim().length > 0)
  .map((line) => JSON.parse(line) as Record<string, any>);

const hosts = [...new Set(real.map((f) => f.host as string))].sort();
const alias = new Map(hosts.map((host, index) => [host, `host-${index + 1}.example.test`]));
const redactHost = (value: string): string => {
  let out = value;
  for (const [realHost, fake] of alias) out = out.replaceAll(realHost, fake);
  return out;
};

const redacted = real.map((finding, index) => ({
  ...finding,
  host: redactHost(finding.host ?? ""),
  url: finding.url ? redactHost(finding.url) : undefined,
  "matched-at": finding["matched-at"] ? redactHost(finding["matched-at"]) : undefined,
  ip: finding.ip ? `192.0.2.${(index % 254) + 1}` : undefined, // TEST-NET-1
  // Request/response bodies and curl lines can carry real headers, cookies and
  // payloads. The Go parser only needs them to be present and string-typed.
  request: finding.request ? `GET / HTTP/1.1\r\nHost: ${redactHost(finding.host ?? "")}\r\n\r\n` : undefined,
  response: finding.response ? "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>" : undefined,
  "curl-command": finding["curl-command"] ? `curl -X 'GET' 'https://${redactHost(finding.host ?? "")}/'` : undefined,
  "extracted-results": finding["extracted-results"] ? ["redacted"] : undefined,
  "template-encoded": undefined, // a base64 copy of the whole template; large and pointless here
  // An absolute path into whoever's checkout produced the run. Relative is both
  // reproducible and free of the developer's home directory.
  "template-path": typeof finding["template-path"] === "string"
    ? finding["template-path"].replace(/^.*\/nuclei\//, "")
    : undefined,
}));

// Every one of the 88 real findings is `medium` from one of two templates, so
// the severity breakdown and the unknown-severity coercion have no natural
// coverage. Derive the missing severities from a real record's structure.
const template = redacted[0];
const variants = ["critical", "high", "low", "info"].map((severity, index) => ({
  ...template,
  host: `sev-${severity}.example.test`,
  "matched-at": `https://sev-${severity}.example.test`,
  url: `https://sev-${severity}.example.test`,
  "template-id": `synthetic-${severity}-finding`,
  "matcher-name": `synthetic-${severity}`,
  ip: `192.0.2.${200 + index}`,
  info: { ...template.info, name: `Synthetic ${severity} finding`, severity },
}));

const name = "safe-non-prod-20260101-000000.jsonl";
writeFileSync(
  resolve(SNAPSHOT, "results", name),
  `${[...redacted, ...variants].map((f) => JSON.stringify(f)).join("\n")}\n`,
);

// A second run, holding only the pathological records. Keeping them out of the
// happy-path file matters: a finding with no resolvable host makes
// inventory-store.countFindings throw, while scans-io.parseFindings silently
// drops it — an inconsistency the Go port has to decide about deliberately, and
// which needs a fixture either way.
const edgeName = "safe-edge-20260101-000001.jsonl";
const edges = [
  // An unrecognised severity must coerce to "unknown".
  { ...template, host: "edge-1.example.test", "template-id": "edge-bad-severity", info: { ...template.info, severity: "moderate" } },
  // No `host`: the reader falls back to `matched-at`, then to `url`.
  { ...template, host: undefined, "matched-at": "https://edge-2.example.test:8443/path", "template-id": "edge-host-from-matched-at" },
  { ...template, host: undefined, "matched-at": undefined, url: "https://edge-3.example.test", "template-id": "edge-host-from-url" },
  // A bare host:port rather than a URL — split on ':' instead of URL-parsed.
  { ...template, host: undefined, "matched-at": "edge-4.example.test:443", url: undefined, "template-id": "edge-host-port" },
  // No name: the reader falls back to the template id.
  { ...template, host: "edge-5.example.test", "template-id": "edge-no-name", info: { ...template.info, name: undefined } },
];
writeFileSync(
  resolve(SNAPSHOT, "results", edgeName),
  // A trailing blank line and an unparseable line: both readers must tolerate
  // blanks; only one of them tolerates the garbage.
  `${edges.map((f) => JSON.stringify(f)).join("\n")}\n\nnot valid json\n`,
);

// Nothing identifying live infrastructure may survive into the committed file.
// The estate's own template ids, names and authors (flanksource-*-baseline) are
// deliberately allowed: templates/ is already tracked in git, so they are not a
// disclosure — only hosts, addresses, credentials and local paths are.
const written = [name, edgeName]
  .map((file) => readFileSync(resolve(SNAPSHOT, "results", file), "utf8"))
  .join("\n");
const leaks: string[] = [];
for (const host of hosts) {
  if (written.includes(host)) leaks.push(`host ${host}`);
}
for (const zone of inventory.zones) {
  // Any surviving FQDN in a real zone, e.g. "<anything>.flanksource.com".
  const fqdn = new RegExp(`[a-z0-9-]+\\.${zone.replace(/\./g, "\\.")}`, "i");
  const hit = fqdn.exec(written);
  if (hit) leaks.push(`fqdn ${hit[0]} (zone ${zone})`);
}
for (const [label, pattern] of [
  ["absolute path", /\/Users\/|\/home\/[a-z]/i],
  // A real header carries a value; the cookie-security template's matcher names
  // and description legitimately contain the bare words "set-cookie".
  ["cookie header", /set-cookie:\s*\S/i],
  ["authorization header", /authorization:\s*\S/i],
  ["bearer token", /bearer\s+[A-Za-z0-9._-]{16,}/i],
] as const) {
  if (pattern.test(written)) leaks.push(label);
}
if (leaks.length > 0) {
  throw new Error(`redaction failed in ${name}:\n  - ${leaks.join("\n  - ")}`);
}

const severities = [...redacted, ...variants].reduce<Record<string, number>>((acc, f) => {
  const key = f.info?.severity ?? "unknown";
  acc[key] = (acc[key] ?? 0) + 1;
  return acc;
}, {});

console.log(reasons.join("\n"));
console.log(
  JSON.stringify(
    {
      targets: targets.length,
      classes: [...classes].sort(),
      zones: inventory.zones.length,
      profiles: readdirSync(resolve(SNAPSHOT, "config")).length,
      findings: redacted.length,
      findingHosts: alias.size,
      severities,
    },
    null,
    2,
  ),
);
