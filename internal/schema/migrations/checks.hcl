// What a check is, as opposed to what it found.
//
// Every finding carries a full copy of its own check's description — name,
// remediation, references, tags — because until now there was nowhere else to
// put it. That made the catalogue a property of evidence that is designed to be
// deleted: `findings` cascades away with its scan, `finding_states.finding_id`
// goes NULL by design, and what was left of a check somebody still has to fix
// was an id and a severity. The ledger outliving the evidence was the entire
// point of finding_states, and it could not render itself.
//
// Keyed by (engine, check_id) rather than a ulid, for the reason mute_rules is
// keyed by name: this is the identifier that appears in a profile, in a mute
// rule and in whatever ticket cites it, and the same pair is already the
// non-resource half of finding_states_key.
table "checks" {
  schema = schema.public

  column "engine" {
    null = false
    type = text
  }
  column "check_id" {
    null    = false
    type    = text
    comment = "the finding's template_id, e.g. gcp/apikeys_key_exists"
  }

  // Descriptive, and last writer wins within the engine that owns it. A check
  // whose upstream title or remediation is reworded should read the new way
  // everywhere, including on the findings that were open before the rewording:
  // there is one check, not one per run that observed it.
  column "name" {
    null    = false
    type    = text
    default = ""
  }
  column "severity" {
    null    = false
    type    = text
    default = "unknown"
    comment = "as the engine last reported it; finding_states keeps its own copy of the verdict's"
  }
  column "type" {
    null = true
    type = text
  }
  column "remediation" {
    null = true
    type = text
  }
  column "reference" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }
  column "tags" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  column "first_seen" {
    null = false
    type = timestamptz
  }
  column "last_seen" {
    null    = false
    type    = timestamptz
    comment = "the last run that reported this check at all, passing or failing"
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
    columns = [column.engine, column.check_id]
  }

  check "checks_seen_order" {
    expr = "last_seen >= first_seen"
  }

  // No foreign key from finding_states: a check the catalogue has not caught up
  // with must not stop the ledger recording that it failed. The join is a left
  // one and an absent row reads as an unnamed check, which is honest.
  index "checks_severity_idx" {
    columns = [column.severity]
  }
  index "checks_tags_idx" {
    type    = GIN
    columns = [column.tags]
  }
}
