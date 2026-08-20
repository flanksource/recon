// Liveness sweeps and what each host answered.
//
// A probe used to be a response and nothing else: it folded what it saw into
// the targets and the run itself was never recorded. That made "when was this
// host last checked, and what did it say" answerable only from the target it
// happened to overwrite — and only for the most recent sweep.
//
// `id` is also the id of the task group the run drives, so /api/v1/tasks/{id}
// and /api/v1/probe/{id} address the same run.
table "probes" {
  schema = schema.public

  column "id" {
    null    = false
    type    = uuid
    default = sql("generate_ulid()")
  }

  // The resolved selector, stored rather than referenced so a run still
  // describes what it covered after the filter is changed.
  column "selector" {
    null = true
    type = jsonb
  }
  column "total" {
    null    = false
    type    = integer
    default = 0
    comment = "hosts the selector resolved to; the progress denominator"
  }

  column "timeout_ms" {
    null    = false
    type    = integer
    default = 0
  }
  column "concurrency" {
    null    = false
    type    = integer
    default = 0
    comment = "what was asked for; the task worker pool may allow fewer"
  }
  column "follow_redirects" {
    null    = false
    type    = boolean
    default = true
  }

  column "phase" {
    null = false
    type = text
  }
  column "ran_at" {
    null = false
    type = timestamptz
  }
  column "finished_at" {
    null = true
    type = timestamptz
  }
  column "duration_ms" {
    null    = false
    type    = integer
    default = 0
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

  index "probes_ran_at_idx" {
    columns = [column.ran_at]
  }
  index "probes_phase_idx" {
    columns = [column.phase]
  }
}

// One row per host, written the moment that host finishes rather than when the
// sweep does. A row exists if and only if the host has been probed, so absence
// is "still pending" — which is what makes a run readable while it is running
// without writing placeholder rows for every host up front.
table "probe_results" {
  schema = schema.public

  column "probe_id" {
    null = false
    type = uuid
  }
  column "host" {
    null = false
    type = text
  }

  column "url" {
    null = true
    type = text
  }
  column "up" {
    null    = false
    type    = boolean
    default = false
  }
  column "status_code" {
    null = true
    type = integer
  }
  column "response_time_ms" {
    null    = false
    type    = bigint
    default = 0
  }
  column "ip" {
    null = true
    type = text
  }
  column "content_type" {
    null = true
    type = text
  }
  column "error" {
    null = true
    type = text
  }
  column "failure" {
    null    = true
    type    = text
    comment = "why error happened: dns, refused, unreachable, timeout, tls, http, other"
  }
  column "updated" {
    null    = false
    type    = boolean
    default = false
    comment = "the host's inventory record was rewritten from this result"
  }
  column "probed_at" {
    null = false
    type = timestamptz
  }

  primary_key {
    columns = [column.probe_id, column.host]
  }

  foreign_key "probe_results_probe_id_fkey" {
    columns     = [column.probe_id]
    ref_columns = [table.probes.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }

  // Composite rather than on host alone: the query this exists for is one
  // host's history in time order, and Postgres can walk this index backwards
  // for the newest-first case without a descending declaration.
  index "probe_results_host_idx" {
    columns = [column.host, column.probed_at]
  }
}
