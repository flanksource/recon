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
    comment = "full | targeted | explicit"
  }
  column "profile" {
    null    = false
    type    = text
    default = "default"
  }
  column "input" {
    null    = false
    type    = jsonb
    default = sql("'{}'::jsonb")
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

  index "discoveries_ran_at_idx" {
    columns = [column.ran_at]
  }
}

// One row per host a run observed.
//
// There is deliberately no is_known column. Discovery now inventories every
// observed host, so whether it still needs classification is represented by the
// target's unclassified class rather than duplicated run-local state.
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
    null    = false
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
    columns = [column.discovery_id, column.host, column.engine]
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
