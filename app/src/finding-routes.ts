// The addresses a finding is reachable at.
//
// Built and parsed in one place so the link a listing renders and the route the
// app matches cannot drift: a checkId contains slashes, and a builder that
// escaped them where the parser expected them literal would produce links that
// only fail once someone clicks one.

/**
 * The page for one check.
 *
 * A checkId is itself a path (`gcp/bigquery_dataset_cmk_encryption`), and its
 * slashes are kept literal so the URL reads as the check it is about rather
 * than as an opaque blob — the same reason a profile and a target are
 * addressable. Every segment is still escaped individually, so a checkId
 * carrying a `?` or a `#` cannot break out of the path.
 */
export function findingGroupHref(engine: string, checkId: string): string {
  return `/findings/${[engine, ...checkId.split("/")].map(encodeURIComponent).join("/")}`;
}

/** The inverse of {@link findingGroupHref}: the tail after the engine segment. */
export function parseCheckId(tail: string): string {
  return tail.split("/").map(decodeURIComponent).join("/");
}

/** The page for one finding — the evidence a single engine run recorded. */
export function findingHref(id: string): string {
  return `/findings/${encodeURIComponent(id)}`;
}

/** The page for one resource. */
export function resourceHref(id: string): string {
  return `/resources/${encodeURIComponent(id)}`;
}
