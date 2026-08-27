// Turns a finding into the draft rule the mute editor opens on.
//
// A rule is nearly always written in response to something a run reported, so
// the editor should open already describing that finding rather than empty.
// Every dimension filled here narrows the rule, and narrowing is the safe
// direction: a suppression that stops matching shows the finding again, while
// one that matches too much hides work nobody has seen.

import type { Finding } from "./types";
import type { MuteRule } from "./mute-types";

/** The path segment addressing a rule that does not exist yet. */
export const NEW_MUTE = "new";

/**
 * The dimensions a draft travels in. One list, used by both directions, so a
 * field cannot be written here and silently ignored when it is read back.
 */
const PREFILL_FIELDS = ["templates", "resources", "resourceKeys", "tags", "severity", "engines"] as const;

/**
 * How much a rule seeded from a finding should cover.
 *
 * Offered as a choice rather than decided here because only the person
 * accepting the finding knows which it is: that one bucket is meant to be
 * public is a different fact from that check being noise everywhere, and a
 * default that guessed wrong would either hide too much or be edited every
 * time.
 */
export type MuteScope =
  | "check-on-resource"
  | "check-on-host"
  | "check-anywhere"
  | "anything-on-resource";

type ScopeSpec = {
  id: MuteScope;
  label: string;
  resource: "resourceKey" | "host" | null;
  templates: boolean;
};

// Narrowest first: the list is read top to bottom by someone deciding how much
// to hide, and the safe end of that range should be the one they reach first.
const SCOPES: ScopeSpec[] = [
  { id: "check-on-resource", label: "This check on this resource", resource: "resourceKey", templates: true },
  { id: "check-on-host", label: "This check on this host", resource: "host", templates: true },
  { id: "check-anywhere", label: "This check everywhere", resource: null, templates: true },
  { id: "anything-on-resource", label: "Anything on this resource", resource: "resourceKey", templates: false },
];

function canonicalResource(finding: Finding): { key: string; label: string } | undefined {
  const resource = finding.resources?.[0];
  if (!resource?.provider || !resource.uid) return undefined;
  return {
    key: `${resource.provider}/${resource.scope ?? ""}/${resource.uid}`,
    label: resource.name || resource.uid,
  };
}

/**
 * The query the rule editor reads a prefilled draft from.
 *
 * Values are comma-separated, the same grammar the CLI and the server's
 * StringList use. Only the dimensions the scope names are sent: a rule that
 * also carried the finding's tags and severity would read as "this check on
 * this resource" while quietly meaning something narrower.
 */
export function mutePrefillQuery(
  finding: Finding,
  // The scan engine the run used. `finding.engine` says the same thing and is
  // preferred when it is set; this stays the caller's override for the places
  // that know the run and hold a finding that does not name one.
  engine?: string,
  scope: MuteScope = "check-on-resource",
): URLSearchParams {
  const spec = SCOPES.find((candidate) => candidate.id === scope) ?? SCOPES[0];
  const params = new URLSearchParams();

  if (spec.templates && finding.checkId) params.set("templates", finding.checkId);

  if (spec.resource === "host" && finding.host) params.set("resources", finding.host);
  if (spec.resource === "resourceKey") {
    const resource = canonicalResource(finding);
    if (resource) params.set("resourceKeys", resource.key);
  }

  const reporting = engine ?? finding.engine;
  if (reporting) params.set("engines", reporting);

  return params;
}

const draftPath = (params: URLSearchParams): string => {
  const query = params.toString();
  return query ? `/mutes/${NEW_MUTE}?${query}` : `/mutes/${NEW_MUTE}`;
};

/** Where a "Mute this finding" choice navigates to. */
export function mutePrefillPath(
  finding: Finding,
  engine?: string,
  scope: MuteScope = "check-on-resource",
): string {
  return draftPath(mutePrefillQuery(finding, engine, scope));
}

/**
 * Where "mute this check everywhere" navigates to.
 *
 * The check-anywhere scope resolves to the check and the engine and nothing
 * else, which is exactly what a listing grouped by check already holds — so it
 * can offer that one scope without picking an arbitrary finding underneath to
 * stand in for the rest. The scopes that name a resource deliberately have no
 * equivalent here: seeding them from whichever affected resource happened to
 * sort first would write a rule about that resource while reading as a rule
 * about the check.
 */
export function muteCheckPath(checkId: string, engine?: string): string {
  const params = new URLSearchParams();
  if (checkId) params.set("templates", checkId);
  if (engine) params.set("engines", engine);
  return draftPath(params);
}

export type MuteScopeOption = {
  id: MuteScope;
  label: string;
  /** The concrete values the scope resolves to, for the item's tooltip. */
  title: string;
  path: string;
};

/**
 * The scopes worth offering for one finding.
 *
 * A scope whose dimensions the finding cannot fill is left out rather than
 * offered and silently widened: "this check on this resource" with no resource
 * is "this check everywhere", which is a different decision.
 */
export function muteScopeOptions(finding: Finding, engine?: string): MuteScopeOption[] {
  const options: MuteScopeOption[] = [];

  for (const spec of SCOPES) {
    if (spec.templates && !finding.checkId) continue;

    const canonical = canonicalResource(finding);
    const resource = spec.resource === "host" ? finding.host : canonical?.key;
    if (spec.resource && !resource) continue;

    // Several engines report the same string for both, and two menu entries
    // producing byte-identical rules is a choice that is not one.
    const path = mutePrefillPath(finding, engine, spec.id);
    if (options.some((option) => option.path === path)) continue;

    options.push({
      id: spec.id,
      label: spec.label,
      title: [
        spec.templates ? finding.checkId : "any check",
        spec.resource ? `on ${spec.resource === "resourceKey" ? canonical?.label : resource}` : "anywhere",
      ]
        .filter(Boolean)
        .join(" "),
      path,
    });
  }

  return options;
}

/** Trims a value down to something that can be part of a rule name. */
function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .slice(0, 48)
    .replace(/^-+|-+$/g, "");
}

/**
 * The last meaningful segment of a resource, which is the part people say.
 *
 * A query string and a fragment are dropped: they address a request rather than
 * the thing the rule is about, and they make a name nobody recognises. The rule
 * still matches on the resource in full — this only decides what it is called.
 */
function resourceLabel(resource: string): string {
  const addressed = resource.split(/[?#]/)[0];
  const segments = addressed.split(/[/\\]/).filter((segment) => segment !== "");
  return segments[segments.length - 1] ?? addressed;
}

/**
 * Names a rule after what it covers.
 *
 * The name is the rule's identity: it is what a run's mutes.json cites and what
 * someone reads months later, so it is derived from the rule's own dimensions
 * rather than generated as an opaque id. It stays editable — this is a starting
 * point, not the last word.
 *
 * Uniqueness is not cosmetic. The server rejects a colliding name so creating
 * a rule can never rewrite somebody else's scope.
 */
export function suggestMuteName(rule: MuteRule, taken: string[] = []): string {
  const parts = [
    rule.templates?.[0] ? slug(rule.templates[0]) : "",
    rule.resourceKeys?.[0]
      ? slug(resourceLabel(rule.resourceKeys[0]))
      : rule.resources?.[0]
        ? slug(resourceLabel(rule.resources[0]))
        : "",
  ].filter((part) => part !== "");

  if (parts.length === 0) {
    const tag = rule.tags?.find((value) => !value.startsWith("!"));
    const fallback = tag ?? rule.severity?.[0] ?? "";
    if (fallback) parts.push(slug(fallback));
  }

  const base = parts.join("-").replace(/^-+|-+$/g, "") || "muted-finding";

  const used = new Set(taken);
  if (!used.has(base)) return base;
  // Terminates: `taken` is finite, so at most one more candidate than it holds.
  for (let suffix = 2; ; suffix += 1) {
    const candidate = `${base}-${suffix}`;
    if (!used.has(candidate)) return candidate;
  }
}

/**
 * Reads a draft back out of the query the link carried.
 *
 * The name is not carried in the link: it is derived from the dimensions that
 * are, by suggestMuteName, once the existing names are known and a collision
 * can be avoided.
 */
export function mutePrefillDraft(search: string): MuteRule {
  const params = new URLSearchParams(search);
  const draft: MuteRule = { name: "" };

  for (const field of PREFILL_FIELDS) {
    const values = (params.get(field) ?? "")
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value !== "");
    // An absent dimension is left absent rather than set to []: on the server an
    // empty list is unconstrained, but writing the key makes a draft that
    // round-trips differently from one that never carried it.
    if (values.length > 0) (draft as Record<string, unknown>)[field] = values;
  }

  return draft;
}
