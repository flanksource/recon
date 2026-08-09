// Discovery runs and what they saw. Replaces the JSON cache the TypeScript
// backend wrote under .gen/.
table "discoveries" {
  schema = schema.public

  column "id" {
    null    = false
    type    = uuid
    default = sql("generate_ulid()")
  }
  column "chain" {
    null    = false
    type    = text
    comment = "full | targeted"
  }
  column "ran_at" {
    null = false
    type = timestamptz
  }
  column "log" {
    null    = true
    type    = text
    comment = "trailing output, bounded — enough to explain a failure, not a transcript"
  }
  column "duration_ms" {
    null = true
    type = integer
  }
  column "failed" {
    null    = false
    type    = bool
    default = false
  }
  column "error" {
    null = true
    type = text
  }
  column "created_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.id]
  }

  check "discoveries_chain_enum" {
    expr = "chain IN ('full', 'targeted')"
  }

  index "discoveries_ran_at_idx" {
    columns = [column.ran_at]
  }
}

// One row per host a run observed.
//
// There is deliberately no is_known column. The TypeScript cache recomputed that
// against the current inventory on every read, so a host classified after the
// run stopped showing as unknown. Storing it would freeze the answer at run
// time; it is a LEFT JOIN against targets instead.
table "discovery_hosts" {
  schema = schema.public

  column "discovery_id" {
    null = false
    type = uuid
  }
  column "host" {
    null = false
    type = text
  }
  column "engine" {
    null    = true
    type    = text
    comment = "which engine produced the observation"
  }
  column "live" {
    null    = false
    type    = bool
    default = false
  }
  column "probe" {
    null    = true
    type    = jsonb
    comment = "the normalised observation record"
  }

  primary_key {
    columns = [column.discovery_id, column.host]
  }

  foreign_key "discovery_hosts_discovery_id_fkey" {
    columns     = [column.discovery_id]
    ref_columns = [table.discoveries.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }

  index "discovery_hosts_host_idx" {
    columns = [column.host]
  }
}

// Hosts seen in the wild that nobody has classified yet. Deliberately outside
// `targets`: adding a host to the inventory is a human decision, and an
// unclassified host must never be swept up by a class-based selector.
table "discovery_unknown_hosts" {
  schema = schema.public

  column "host" {
    null = false
    type = text
  }
  column "first_seen" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }
  column "last_seen" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }
  column "probe" {
    null = true
    type = jsonb
  }

  primary_key {
    columns = [column.host]
  }

  index "discovery_unknown_hosts_last_seen_idx" {
    columns = [column.last_seen]
  }
}
