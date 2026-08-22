// The Go types in internal/api are the source of truth and these mirror them.
// They live here rather than in types.ts because that file is already at the
// size the repo splits at, and because the mute surface is self-contained.

import type { Finding, Identified, Severity } from "./types";

/**
 * A finding someone has decided not to act on.
 *
 * The dimensions are ANDed and the values within one are ORed. An empty
 * dimension is unconstrained rather than unsatisfiable, and a rule that
 * constrains nothing at all is refused by the server — an accidentally
 * universal mute is the one mistake this surface must not let anyone make.
 */
export type MuteRule = Identified & {
  /** Identity, and what a run's mutes.json cites. */
  name: string;
  comment?: string;
  /** Suspends the rule without deleting it. There is no expiry. */
  disabled?: boolean;

  /**
   * Which engines the rule is considered for. Empty means all of them. It is a
   * precondition rather than a selector: on its own it matches no finding, and
   * the server refuses a rule carrying only this.
   */
  engines?: string[];

  /** A target selector over the inventory — which subjects the rule covers. */
  targets?: Record<string, unknown>;

  /**
   * Globs over the resource the evidence names, which is not the same question
   * as `targets`: for Prowler a finding's host is the cloud account and the
   * resource uid is in matchedAt.
   */
  resources?: string[];
  /** Globs over templateId — the check that fired. */
  templates?: string[];
  /** Matched against the finding's tags; a `!` prefix excludes. */
  tags?: string[];
  severity?: Severity[];

  /**
   * A CEL expression over a single `finding` variable, holding the finding
   * exactly as this API renders it. It narrows the dimensions above and can
   * never widen them.
   */
  expr?: string;

  createdAt?: string;
  updatedAt?: string;
};

/** What a rule would have taken out of runs that already finished. */
export type MutePreview = {
  rule: string;
  scan?: string;
  matched: number;
  examined: number;
  findings: Finding[];
  /**
   * Present when the expression could not be evaluated. A rule that errors
   * mutes nothing, so this is the difference between "matched none" and "could
   * not tell".
   */
  errors?: string[];
};

/** The dimensions a rule can select on, in the order the form shows them. */
export const MUTE_DIMENSIONS = [
  "templates",
  "resources",
  "tags",
  "severity",
] as const;

export type MuteDimension = (typeof MUTE_DIMENSIONS)[number];

/**
 * Whether a rule names anything to mute.
 *
 * Mirrors MuteRule.Selects in Go so the form can say why a rule cannot be saved
 * before asking the server. Engines is deliberately not counted, for the same
 * reason it is not counted there.
 */
export function muteSelects(rule: MuteRule): boolean {
  return (
    MUTE_DIMENSIONS.some((dimension) => (rule[dimension]?.length ?? 0) > 0) ||
    Object.keys(rule.targets ?? {}).length > 0 ||
    (rule.expr ?? "").trim() !== ""
  );
}
