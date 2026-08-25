// Findings an operator has decided not to act on.
//
// Keyed by name rather than a ulid: a rule is cited in a run's mutes.json and
// in whatever ticket justified it, and an identifier nobody can read is an
// identifier nobody checks.
//
// The selector columns are deliberately separate rather than one jsonb blob.
// Which checks and which severities a rule covers is what decides whether it
// can be pushed into an engine's own exclusion flags, and that decision should
// be a column read rather than a document parse.
table "mute_rules" {
  schema = schema.public

  column "name" {
    null = false
    type = text
  }

  // Optional. Nothing about a rule is mandatory beyond a name and something to
  // select on — a rule that is tedious to create is a rule people work around.
  column "comment" {
    null = true
    type = text
  }

  // Suspends a rule without deleting it. There is no expiry column, so this is
  // the only way to turn a rule off and still keep it.
  column "disabled" {
    null    = false
    type    = boolean
    default = false
  }

  // Which engines the rule is considered for. Empty means every scan engine.
  // A precondition rather than a selector: on its own it matches no finding.
  column "engines" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  // A store.TargetOpts selector over the inventory — which subjects the rule
  // covers. Resolved to target ids once per run.
  column "targets" {
    null    = false
    type    = jsonb
    default = sql("'{}'::jsonb")
  }

  // Globs over the resource the evidence names, which is a different question
  // from `targets`: for Prowler a finding's host is the cloud account and the
  // resource uid is in matched_at.
  column "resources" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  // Exact canonical resource identities in provider/scope/uid form.
  column "resource_keys" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  column "templates" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  // `!` prefixed values exclude, the same grammar the tag filters use.
  column "tags" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  column "severity" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  // A CEL expression over a single `finding` variable. It narrows the columns
  // above and can never widen them, so what a rule could possibly match stays
  // answerable without evaluating anything.
  column "expr" {
    null = true
    type = text
  }

  column "created_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }
  column "updated_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.name]
  }

  // Mirrors engine_profiles_name_format, so a rule name is always safe to use
  // as a filename fragment and as a key in a run's mutes.json.
  check "mute_rules_name_format" {
    expr = "name ~ '^[a-z0-9][a-z0-9-]*$'"
  }

  index "mute_rules_disabled_idx" {
    columns = [column.disabled]
  }
}
