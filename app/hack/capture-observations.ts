// Capture input/expected pairs for the observation normalizer before it is
// ported to Go. `applyObservation` is the subtlest piece of the TypeScript
// backend — CPE string-vs-object forms, AS-prefix stripping, TLS
// fingerprint_hash string-vs-{sha256}, port clamping, and the `defined()`
// pruning that drops all-undefined sections. Replaying these pairs is what
// proves the Go port is exact.
//
//   pnpm --dir app exec tsx hack/capture-observations.ts
//
// Writes ../contract/fixtures/observations.json (committed — the records
// describe live hosts but carry no credentials, and the Go suite needs them).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { applyObservation, getObservationHost } from "../server/inventory-observation.ts";
import type { TargetDocument } from "../src/types.ts";

const NUCLEI_DIR = resolve(import.meta.dirname, "..", "..");
const TIMESTAMP = "2026-08-09T00:00:00.000Z";
const EARLIER = "2026-01-15T09:30:00.000Z";

type JsonRecord = Record<string, unknown>;

type Case = {
  name: string;
  target: TargetDocument;
  record: unknown;
  timestamp: string;
  expected: TargetDocument;
};

const stub = (host: string): TargetDocument => ({
  $schema: "../target.schema.json",
  version: 1,
  host,
  class: "non-prod",
  profiles: ["safe"],
  tags: [],
});

/** A target carrying a full previous snapshot, to prove what a failure preserves. */
const withPriorSnapshot = (host: string, record: unknown): TargetDocument => ({
  ...applyObservation(stub(host), record, EARLIER),
  scan: { last_scan: EARLIER, last_findings: 3 },
});

const records: unknown[] = readFileSync(resolve(NUCLEI_DIR, ".gen/discovered.json"), "utf8")
  .split("\n")
  .filter((line) => line.trim().length > 0)
  .map((line) => JSON.parse(line));

if (records.length === 0) throw new Error(".gen/discovered.json is empty — run a discovery first");

const cases: Case[] = [];
const add = (name: string, target: TargetDocument, record: unknown, timestamp = TIMESTAMP) => {
  cases.push({ name, target, record, timestamp, expected: applyObservation(target, record, timestamp) });
};

for (const record of records) {
  const host = getObservationHost(record);
  // 1. A brand-new target: every section is written from scratch.
  add(`fresh/${host}`, stub(host), record);
  // 2. A target already observed: first_observed must survive, last_seen must move.
  add(`reobserved/${host}`, withPriorSnapshot(host, record), record);
}

// 3. The failure short-circuit. `.gen/discovered.json` holds no failed probes,
// but over 100 of the checked-in targets are in exactly this state, so the
// branch that writes only observed.{last_attempt,error} — leaving network/http/
// tech/tls untouched — has to be pinned.
const sample = records[0];
const sampleHost = getObservationHost(sample);
for (const [name, error] of [
  ["with-error", 'cause="no address found for host"'],
  ["without-error", undefined],
] as const) {
  const failed = error === undefined
    ? { input: sampleHost, failed: true }
    : { input: sampleHost, failed: true, error };
  add(`failed-fresh/${name}`, stub(sampleHost), failed);
  add(`failed-preserves-snapshot/${name}`, withPriorSnapshot(sampleHost, sample), failed);
}

// 4. Synthetic records for the branches the live discovery cache never hits.
// The inputs are hand-built, but every `expected` is still produced by the real
// TypeScript implementation, so the expectations stay authoritative.
const synthetic: Array<[string, JsonRecord]> = [
  // -- TLS: fingerprint_hash is a string on some httpx versions, {sha256} on others.
  ["tls/fingerprint-string", { tls: { tls_version: "tls13", cipher: "TLS_AES_128_GCM_SHA256", fingerprint_hash: "abc123" } }],
  ["tls/fingerprint-sha256-object", { tls: { tls_version: "tls12", fingerprint_hash: { md5: "m", sha1: "s", sha256: "def456" } } }],
  ["tls/full-certificate", {
    tls: {
      tls_version: "tls13", cipher: "TLS_AES_256_GCM_SHA384",
      subject_dn: "CN=example.test", subject_cn: "example.test",
      subject_org: ["Example Org", "Example Org"], subject_an: ["z.example.test", "a.example.test"],
      issuer_dn: "CN=Test CA", issuer_cn: "Test CA", issuer_org: ["Test CA Inc"],
      not_before: "2026-01-01T00:00:00Z", not_after: "2027-01-01T00:00:00Z",
      serial: "0A:1B", expired: false, self_signed: true, mismatched: false,
      revoked: false, untrusted: true, wildcard_certificate: true,
      fingerprint_hash: { sha256: "cafe" },
    },
  }],
  ["tls/empty-object-drops-section", { tls: {} }],
  ["tls/not-an-object", { tls: "tls13" }],
  // -- ASN: httpx emits "AS15169"; the number must be stripped, with legacy fallbacks.
  ["asn/as-prefixed", { asn: { as_number: "AS15169", as_name: "GOOGLE", as_country: "US", as_range: "8.8.8.0/24" } }],
  ["asn/as-prefix-lowercase", { asn: { as_number: "as15169", as_name: "GOOGLE" } }],
  ["asn/legacy-field-names", { asn: { number: 64512, name: "Legacy", country: "DE", range: "10.0.0.0/8" } }],
  ["asn/empty-object-drops-section", { asn: {} }],
  ["asn/unparseable-number", { asn: { as_number: "ASXYZ", as_name: "Broken" } }],
  // -- CPE: bare strings split on ':' (vendor=[3], product=[4]) vs the object form.
  ["cpe/bare-strings", { cpe: ["cpe:2.3:a:nginx:nginx:1.25.3", "cpe:/a:apache:httpd"] }],
  ["cpe/too-short-to-split", { cpe: ["cpe:2.3:a"] }],
  ["cpe/mixed-and-invalid", { cpe: ["cpe:2.3:a:v:p:1", { cpe: "cpe:obj", vendor: "V", product: "P" }, { vendor: "no-cpe-key" }, 42] }],
  // -- CDN: a name with no boolean still yields enabled:false.
  ["cdn/name-only", { cdn_name: "cloudflare" }],
  ["cdn/enabled-true", { cdn: true, cdn_name: "fastly", cdn_type: "waf" }],
  // -- Ports: out-of-range dropped, duplicates removed, sorted numerically.
  ["ports/clamped-deduped-sorted", { open_ports: [0, 65536, -1, 8443, 443, 443, 80, "22", 1.5, null] }],
  // -- Numeric coercion: httpx sends port as a string; floats are truncated.
  ["http/string-port-and-float-status", { port: "8443", status_code: 200.9 }],
  // -- `title`/`webserver` bypass the non-empty-string helper, so "" survives.
  ["http/empty-strings-preserved", { title: "", webserver: "", content_type: "text/html" }],
  // -- known_paths / login_methods are deduped and sorted.
  ["http/paths-and-login-methods", {
    known_paths: ["/login", "/admin", "/login"],
    login_methods: ["OAuth 2.0", "Basic", "OAuth 2.0", "NTLM", "Negotiate"],
  }],
  // -- Address lists are deduped and sorted.
  ["network/address-dedupe-sort", {
    a: ["10.0.0.2", "10.0.0.1", "10.0.0.1"], aaaa: ["::2", "::1"], cname: ["b.test", "a.test"],
    resolvers: ["1.1.1.1:53", "1.1.1.1:53"],
  }],
];

const SYNTHETIC_HOST = "synthetic.example.test";
for (const [name, extra] of synthetic) {
  add(`synthetic/${name}`, stub(SYNTHETIC_HOST), { input: SYNTHETIC_HOST, ...extra });
}
// The host is derived from `url` when `input` is absent, and lowercased.
add("synthetic/host/from-url-uppercased", stub("upper.example.test"), {
  url: "https://UPPER.example.test:8443/path",
});

const out = resolve(NUCLEI_DIR, "contract/fixtures");
mkdirSync(out, { recursive: true });
writeFileSync(resolve(out, "observations.json"), `${JSON.stringify(cases, null, 2)}\n`);

const branches = {
  total: cases.length,
  fresh: cases.filter((c) => c.name.startsWith("fresh/")).length,
  reobserved: cases.filter((c) => c.name.startsWith("reobserved/")).length,
  failed: cases.filter((c) => c.name.startsWith("failed")).length,
  synthetic: cases.filter((c) => c.name.startsWith("synthetic/")).length,
  withTls: cases.filter((c) => c.expected.tls !== undefined).length,
  withCpe: cases.filter((c) => c.expected.tech?.cpe !== undefined).length,
  withAsn: cases.filter((c) => c.expected.network?.asn !== undefined).length,
  withCdn: cases.filter((c) => c.expected.network?.cdn !== undefined).length,
  withLoginMethods: cases.filter((c) => c.expected.http?.login_methods !== undefined).length,
};
console.log(JSON.stringify(branches, null, 2));
