import type { TargetDocument } from "../src/types.ts";

type JsonObject = Record<string, unknown>;

function object(value: unknown): JsonObject | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function string(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function number(value: unknown): number | undefined {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function boolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function strings(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const values = [...new Set(value.filter((item): item is string => typeof item === "string"))].sort();
  return values.length > 0 ? values : undefined;
}

function integers(value: unknown): number[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const values = [
    ...new Set(
      value
        .map(number)
        .filter(
          (item): item is number =>
            item !== undefined && Number.isInteger(item) && item >= 1 && item <= 65535,
        ),
    ),
  ].sort((left, right) => left - right);
  return values.length > 0 ? values : undefined;
}

function defined<T extends JsonObject>(value: T): T | undefined {
  return Object.values(value).some((item) => item !== undefined) ? value : undefined;
}

function normalizeCpe(value: unknown): Array<{ product?: string; vendor?: string; cpe: string }> | undefined {
  if (!Array.isArray(value)) return undefined;
  const result = value.flatMap((entry) => {
    if (typeof entry === "string") {
      const parts = entry.split(":");
      return [{ cpe: entry, vendor: parts[3], product: parts[4] }];
    }
    const item = object(entry);
    const cpe = string(item?.cpe);
    return cpe ? [{ cpe, product: string(item?.product), vendor: string(item?.vendor) }] : [];
  });
  return result.length > 0 ? result : undefined;
}

function normalizeTls(value: unknown): JsonObject | undefined {
  const tls = object(value);
  if (!tls) return undefined;
  const fingerprint = object(tls.fingerprint_hash);
  return defined({
    tls_version: string(tls.tls_version),
    cipher: string(tls.cipher),
    subject_dn: string(tls.subject_dn),
    subject_cn: string(tls.subject_cn),
    subject_org: strings(tls.subject_org),
    subject_an: strings(tls.subject_an),
    issuer_dn: string(tls.issuer_dn),
    issuer_cn: string(tls.issuer_cn),
    issuer_org: strings(tls.issuer_org),
    not_before: string(tls.not_before),
    not_after: string(tls.not_after),
    serial: string(tls.serial),
    expired: boolean(tls.expired),
    self_signed: boolean(tls.self_signed),
    mismatched: boolean(tls.mismatched),
    revoked: boolean(tls.revoked),
    untrusted: boolean(tls.untrusted),
    wildcard_certificate: boolean(tls.wildcard_certificate),
    fingerprint_hash: string(tls.fingerprint_hash) ?? string(fingerprint?.sha256),
  });
}

function normalizeNetwork(record: JsonObject): JsonObject | undefined {
  const asn = object(record.asn);
  const asNumber = string(asn?.as_number)?.replace(/^AS/i, "");
  const cdnName = string(record.cdn_name);
  const cdnType = string(record.cdn_type);
  const cdnEnabled = boolean(record.cdn);
  return defined({
    ip: string(record.host_ip),
    ipv4: strings(record.a),
    ipv6: strings(record.aaaa),
    cname: strings(record.cname),
    resolvers: strings(record.resolvers),
    open_ports: integers(record.open_ports),
    cdn:
      cdnEnabled === undefined && !cdnName && !cdnType
        ? undefined
        : defined({ enabled: cdnEnabled ?? false, name: cdnName, type: cdnType }),
    asn: asn
      ? defined({
          number: asNumber ? number(asNumber) : number(asn.number),
          name: string(asn.as_name) ?? string(asn.name),
          country: string(asn.as_country) ?? string(asn.country),
          range: string(asn.as_range) ?? string(asn.range),
        })
      : undefined,
  });
}

function normalizeHttp(record: JsonObject): JsonObject | undefined {
  const port = number(record.port);
  const statusCode = number(record.status_code);
  return defined({
    url: string(record.url),
    scheme: string(record.scheme),
    port: port === undefined ? undefined : Math.trunc(port),
    status_code: statusCode === undefined ? undefined : Math.trunc(statusCode),
    title: typeof record.title === "string" ? record.title : undefined,
    webserver: typeof record.webserver === "string" ? record.webserver : undefined,
    content_type: typeof record.content_type === "string" ? record.content_type : undefined,
    location: typeof record.location === "string" ? record.location : undefined,
    response_time: typeof record.time === "string" ? record.time : undefined,
    known_paths: strings(record.known_paths),
    login_methods: strings(record.login_methods),
    failed: boolean(record.failed),
  });
}

function observationHost(record: JsonObject): string {
  const input = string(record.input);
  if (input) return input.toLowerCase();
  const url = string(record.url);
  if (!url) throw new Error("httpx observation must contain input or url");
  return new URL(url).hostname.toLowerCase();
}

export function getObservationHost(value: unknown): string {
  const record = object(value);
  if (!record) throw new Error("httpx observation must be an object");
  return observationHost(record);
}

export function applyObservation(
  target: TargetDocument,
  value: unknown,
  timestamp: string,
): TargetDocument {
  const record = object(value);
  if (!record) throw new Error("httpx observation must be an object");
  const host = observationHost(record);
  if (host !== target.host) throw new Error(`observation host ${host} does not match ${target.host}`);
  if (record.failed === true) {
    const error = string(record.error) ?? "httpx probe failed";
    return { ...target, observed: { ...target.observed, last_attempt: timestamp, error } };
  }
  return {
    ...target,
    observed: {
      first_observed: string(target.observed?.first_observed) ?? timestamp,
      last_seen: timestamp,
      last_attempt: timestamp,
    },
    network: normalizeNetwork(record),
    http: normalizeHttp(record),
    tech: defined({ names: strings(record.tech), cpe: normalizeCpe(record.cpe) }),
    tls: normalizeTls(record.tls),
  };
}
