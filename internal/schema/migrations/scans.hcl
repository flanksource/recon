// A scan run and its findings. `name` is the engine artifact's basename and is
// the stable external identity: it is what the runs list deep-links and what the
// CLI accepts.
table "scans" {
  schema = schema.public

  column "id" {
    null    = false
    type    = uuid
    default = sql("generate_ulid()")
  }
  column "name" {
    null    = false
    type    = text
    comment = "<engine>-<label>-<timestamp>.jsonl"
  }

  column "engine" {
    null = false
    type = text
  }
  column "engine_version" {
    null    = true
    type    = text
    comment = "resolved at run time, so a run stays reproducible"
  }
  column "profile" {
    null = false
    type = text
  }

  // The resolved selector. Stored rather than referenced by name so a run still
  // describes exactly what it covered after the filter is changed.
  column "selector" {
    null = true
    type = jsonb
  }
  column "endpoint_count" {
    null    = false
    type    = integer
    default = 0
  }

  column "phase" {
    null = false
    type = text
  }
  column "started_at" {
    null = false
    type = timestamptz
  }
  column "finished_at" {
    null = true
    type = timestamptz
  }
  column "duration_ms" {
    null    = false
    type    = bigint
    default = 0
    comment = "wall-clock runtime measured by recon"
  }
  column "exit_code" {
    null = true
    type = integer
  }
  column "error" {
    null = true
    type = text
  }
  column "command" {
    null = true
    type = sql("text[]")
  }
  column "stats" {
    null = true
    type = jsonb
  }
  column "severities" {
    null    = false
    type    = jsonb
    default = sql("'{}'::jsonb")
    comment = "per-severity counts, denormalised for the runs list"
  }
  // Findings a mute rule removed after the engine reported them. Recorded
  // because the rows themselves are not: without a count, a muted run is
  // indistinguishable from a clean one. Checks a rule stopped from running are
  // not counted here — they produced nothing to count — and mutes.json in the
  // run's artifact directory says which rules those were.
  column "muted" {
    null    = false
    type    = integer
    default = 0
  }
  column "result_path" {
    null    = true
    type    = text
    comment = "retained artifact directory: results/<engine>/<date>/<name>"
  }
  column "created_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.id]
  }

  index "scans_name_key" {
    unique  = true
    columns = [column.name]
  }

  index "scans_started_at_idx" {
    columns = [column.started_at]
  }
  index "scans_engine_idx" {
    columns = [column.engine, column.profile]
  }
}

// Process output is split from scans so listing runs never reads megabytes of
// evidence. A row exists even when both streams were empty, distinguishing a
// captured empty process from a legacy scan whose output is unavailable.
table "scan_outputs" {
  schema = schema.public

  column "scan_id" {
    null = false
    type = uuid
  }
  column "stdout" {
    null    = false
    type    = text
    default = ""
  }
  column "stderr" {
    null    = false
    type    = text
    default = ""
  }
  column "stdout_truncated" {
    null    = false
    type    = boolean
    default = false
  }
  column "stderr_truncated" {
    null    = false
    type    = boolean
    default = false
  }

  primary_key {
    columns = [column.scan_id]
  }

  foreign_key "scan_outputs_scan_id_fkey" {
    columns     = [column.scan_id]
    ref_columns = [table.scans.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }
}

// One row per line of engine output. The typed columns are what the UI filters
// and groups on; `raw` keeps the engine's original object so a finding can be
// rendered in full without re-reading an artifact that may have been pruned.
table "findings" {
  schema = schema.public

  column "id" {
    null    = false
    type    = uuid
    default = sql("generate_ulid()")
  }
  column "scan_id" {
    null = false
    type = uuid
  }
  column "target_id" {
    null    = true
    type    = text
    comment = "selected inventory target; no foreign key so finding history survives target deletion"
  }
  column "line_no" {
    null    = false
    type    = integer
    comment = "1-based; preserves the engine's output order"
  }

  column "template_id" {
    null = false
    type = text
  }
  column "name" {
    null = false
    type = text
  }
  column "severity" {
    null = false
    type = text
  }
  column "host" {
    null = false
    type = text
  }
  column "matched_at" {
    null = false
    type = text
  }
  column "matcher_name" {
    null = true
    type = text
  }
  column "type" {
    null = true
    type = text
  }
  column "tags" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }
  column "timestamp" {
    null = true
    type = timestamptz
  }
  column "extracted" {
    null = true
    type = sql("text[]")
  }
  column "remediation" {
    null = true
    type = text
  }
  column "reference" {
    null = true
    type = sql("text[]")
  }
  column "curl" {
    null = true
    type = text
  }
  column "request" {
    null = true
    type = text
  }
  column "response" {
    null = true
    type = text
  }
  column "raw" {
    null = true
    type = jsonb
  }

  primary_key {
    columns = [column.id]
  }

  foreign_key "findings_scan_id_fkey" {
    columns     = [column.scan_id]
    ref_columns = [table.scans.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }

  index "findings_scan_line_key" {
    unique  = true
    columns = [column.scan_id, column.line_no]
  }
  index "findings_host_idx" {
    columns = [column.host]
  }
  index "findings_target_idx" {
    columns = [column.target_id]
  }
  index "findings_severity_idx" {
    columns = [column.severity]
  }
  index "findings_template_idx" {
    columns = [column.template_id]
  }
}
