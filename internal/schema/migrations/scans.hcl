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

  // The check this is an instance of. Half of a finding's identity — the other
  // half is the resource — and what stored mute rules match against. OCSF
  // records it twice more, in finding_info.uid and metadata.event_code, but a
  // jsonb path cannot carry an index.
  column "check_id" {
    null = false
    type = text
  }
  // Which scanner produced this. Was `type`, which named neither a type nor
  // anything else consistently.
  column "engine" {
    null = true
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
  // What kind of verdict this evidence is, in recon's vocabulary rather than the
  // engine's.
  //
  // The lifecycle used to read `matcher_name = 'MANUAL'`, which worked only
  // because prowler writes its OCSF status_code into a column nuclei means as
  // the matcher that fired. Two engines, one column, two meanings — and any
  // engine that ever names a matcher MANUAL would have minted manual states.
  column "verdict" {
    null    = false
    type    = text
    default = "fail"
    comment = "fail | manual; manual is a verdict a human still owes"
  }
  // Recon's own cross-cutting labels, which OCSF has no equivalent for. The
  // check catalogue is built from these and the UI filters on them, so they stay
  // an indexed column as well as being projected into finding_info.types.
  column "tags" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }

  // The OCSF scalars. class_uid, category_uid, type_uid, activity_id,
  // severity_id and time are all required by the schema, so none is nullable —
  // a row that could not answer them would not be an OCSF record.
  column "class_uid" {
    null    = false
    type    = integer
    default = 2004
    comment = "OCSF Detection Finding; category_uid * 1000 + the class's own uid"
  }
  column "category_uid" {
    null    = false
    type    = integer
    default = 2
    comment = "OCSF Findings category"
  }
  column "type_uid" {
    null    = false
    type    = bigint
    comment = "class_uid * 100 + activity_id"
  }
  column "activity_id" {
    null    = false
    type    = integer
    default = 1
    comment = "0 Unknown | 1 Create | 2 Update | 3 Close | 99 Other"
  }
  column "severity_id" {
    null    = false
    type    = integer
    comment = "0 Unknown | 1 Informational | 2 Low | 3 Medium | 4 High | 5 Critical | 6 Fatal | 99 Other"
  }
  // Where the finding is in triage, which is OCSF's question and a different
  // one from `verdict`. Note this is the enum the finding classes define, not
  // the activity outcome the attribute dictionary defines under the same name.
  column "status_id" {
    null    = true
    type    = integer
    comment = "0 Unknown | 1 New | 2 In Progress | 3 Suppressed | 4 Resolved | 5 Archived | 99 Other"
  }
  column "status_code" {
    null = true
    type = text
  }
  column "status_detail" {
    null = true
    type = text
  }
  column "time" {
    null = true
    type = timestamptz
  }

  // What it means for this to be true, which is a different question from what
  // was found and is the half of a finding triage actually reads. OCSF puts
  // both at the event level rather than inside finding_info: `impact` is the
  // consequence and `risk_details` the reasoning, and different engines fill
  // different ones — nuclei writes the first, prowler the second.
  column "impact" {
    null = true
    type = text
  }
  column "risk_details" {
    null = true
    type = text
  }

  // One column per OCSF object rather than a single blob holding the record.
  // The list paths select what they render and no more — the fix that stopped a
  // page of findings dragging every engine's payload through the database — and
  // one column would put that straight back.
  column "finding_info" {
    null = true
    type = jsonb
  }
  column "metadata" {
    null = true
    type = jsonb
  }
  column "remediation" {
    null = true
    type = jsonb
  }
  column "cloud" {
    null = true
    type = jsonb
  }
  column "vulnerabilities" {
    null = true
    type = jsonb
  }
  column "observables" {
    null = true
    type = jsonb
  }
  column "unmapped" {
    null    = true
    type    = jsonb
    comment = "OCSF's own escape hatch for what an engine reported and the schema has no home for"
  }

  // The one part of a finding with no natural size: an HTTP exchange, a
  // control's assertions, a block of matched source. Excluded from every list
  // path and bounded on the way in, the way scan_outputs already bounds stdout
  // and stderr — the column this replaced had no limit at all.
  column "evidences" {
    null = true
    type = jsonb
  }
  column "evidences_truncated" {
    null    = false
    type    = boolean
    default = false
  }
  // The primary subject the evidence is about. A record may name several and
  // they all become resources, but the lifecycle keys on one: a check has a
  // single subject, and counting its verdict against every resource it merely
  // mentioned would resolve findings on things the check never judged.
  column "resource_id" {
    null    = true
    type    = uuid
    comment = "NULL for an engine that names no resource recon has recorded"
  }

  primary_key {
    columns = [column.id]
  }

  // A foreign key here and deliberately none on target_id: a target is an
  // external identity a person can delete, so finding history has to outlive it,
  // while a resource is a row this subsystem owns and never deletes.
  foreign_key "findings_resource_id_fkey" {
    columns     = [column.resource_id]
    ref_columns = [table.resources.column.id]
    on_update   = NO_ACTION
    on_delete   = SET_NULL
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
    columns = [column.severity_id]
  }
  index "findings_check_idx" {
    columns = [column.check_id]
  }
  // The catalogue's own key, and how a finding finds the check that describes
  // it once its evidence is gone.
  index "findings_engine_check_idx" {
    columns = [column.engine, column.check_id]
  }

  // OCSF 1.5.0 defines 0-5 and 99 on the finding classes. `main` has since added
  // 6 (Deleted); widening this is a one-line change when the pinned version moves.
  check "findings_status_id_known" {
    expr = "status_id IS NULL OR status_id IN (0, 1, 2, 3, 4, 5, 99)"
  }
  check "findings_severity_id_known" {
    expr = "severity_id IN (0, 1, 2, 3, 4, 5, 6, 99)"
  }
  // The composition OCSF states, checked rather than trusted: a row whose
  // type_uid disagrees with its class and activity is not a record any other
  // OCSF consumer can read.
  check "findings_type_uid_composed" {
    expr = "type_uid = class_uid::bigint * 100 + activity_id"
  }
  index "findings_resource_idx" {
    columns = [column.resource_id]
  }
  // Tags are filtered by containment on both tables; resources has carried the
  // GIN for that since it was written and findings was simply missed.
  index "findings_tags_idx" {
    type    = GIN
    columns = [column.tags]
  }
}

// Every subject a finding names, not only the one its verdict is about.
//
// A check that fails against forty buckets names forty. findings.resource_id
// records the one the lifecycle keys on, and until this table the other
// thirty-nine survived only inside the raw blob — which is engine-specific, is
// not queryable, and is being removed.
//
// The relation also restores identity that OCSF does not carry per resource. A
// resource is keyed by (provider, scope, uid), but OCSF 1.5.0 puts the account
// once at the event level in cloud.account.uid rather than on each entry of its
// resources array, so no amount of re-reading the record reconstitutes the key.
// Joining the table that already holds it does.
table "finding_resources" {
  schema = schema.public

  column "finding_id" {
    null = false
    type = uuid
  }
  column "resource_id" {
    null = false
    type = uuid
  }
  // The position the engine's own record named it in. Order is evidence: the
  // first resource is the subject the verdict is about, and a report that lists
  // a bucket before its project means something a set would discard.
  column "ordinal" {
    null    = false
    type    = integer
    comment = "0-based position in the record's own resource list"
  }

  // Keyed by the pair rather than by (finding, ordinal): a record naming the
  // same resource twice is describing one subject, and two rows for it would
  // double every count taken through this table.
  primary_key {
    columns = [column.finding_id, column.resource_id]
  }

  foreign_key "finding_resources_finding_id_fkey" {
    columns     = [column.finding_id]
    ref_columns = [table.findings.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }

  foreign_key "finding_resources_resource_id_fkey" {
    columns     = [column.resource_id]
    ref_columns = [table.resources.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }

  // Answering "what has been reported about this resource" without scanning
  // every finding ever recorded.
  index "finding_resources_resource_idx" {
    columns = [column.resource_id]
  }
}

// What is currently true about one check on one resource.
//
// The findings table is per-run evidence: two runs of the same profile write two
// complete copies, and nothing in them says which of the first run's findings
// the second one fixed. Measured on two runs an hour apart, 65 failures became
// 49 — sixteen problems genuinely resolved, indistinguishable from the rest.
// This table is where that difference is recorded.
//
// One row per (resource, engine, check), including checks that have only ever
// passed: 141 of one report's 190 verdicts are passes, and that ledger is the
// compliance posture.
table "finding_states" {
  schema = schema.public

  column "id" {
    null    = false
    type    = uuid
    default = sql("generate_ulid()")
  }
  column "resource_id" {
    null = false
    type = uuid
  }
  // In the key so a check id that collides across engines never merges two
  // ledgers. The profile deliberately is not: "is this check failing on this
  // resource" is one fact however the run was configured.
  column "engine" {
    null = false
    type = text
  }
  column "check_id" {
    null    = false
    type    = text
    comment = "the finding's template_id, e.g. gcp/apikeys_key_exists"
  }

  column "status" {
    null    = false
    type    = text
    comment = "open | resolved | muted | manual"
  }
  column "severity" {
    null    = false
    type    = text
    default = "unknown"
    comment = "of the last failing verdict; kept after resolution so the history reads"
  }
  column "reason" {
    null    = true
    type    = text
    comment = "passed | resource-absent | not-reported | mute:<rule> | provider-suppressed"
  }

  column "first_seen" {
    null    = false
    type    = timestamptz
    comment = "first verdict of any kind"
  }
  column "last_seen" {
    null    = false
    type    = timestamptz
    comment = "last verdict of any kind; a stale value means nobody re-checked"
  }
  column "last_open_at" {
    null = true
    type = timestamptz
  }
  column "resolved_at" {
    null    = true
    type    = timestamptz
    comment = "when it last stopped being open or manual; not a test for whether it ever failed — see occurrences"
  }

  column "first_scan_id" {
    null = true
    type = uuid
  }
  column "last_scan_id" {
    null    = false
    type    = uuid
    comment = "the run that produced the current status; absence is `last_scan_id <> this run`"
  }
  column "open_scan_id" {
    null    = true
    type    = uuid
    comment = "the run that most recently opened it, unchanged while it stays open"
  }
  column "finding_id" {
    null    = true
    type    = uuid
    comment = "the evidence while open, NULL once it is not"
  }

  // Which rule accepted this, as a value rather than a substring of `reason`.
  //
  // No foreign key: a rule is an external identity a person deletes, and the
  // attribution has to outlive it long enough for the delete to reopen what it
  // suppressed — the same reasoning target_id carries on findings.
  column "muted_by" {
    null    = true
    type    = text
    comment = "mute_rules.name while status is muted, NULL once it is not"
  }

  // The canonical answer to "has this ever actually failed", and the only one.
  //
  // A check that has only ever passed is status `resolved` with reason `passed`,
  // which is indistinguishable by status alone from one that failed and was
  // fixed. `resolved_at` looks like it should tell them apart and does not: it is
  // set only when a state leaves `open` or `manual`, so a row that went open →
  // muted → passed carries occurrences > 0 and resolved_at NULL and reads as
  // "never failed" under that test and "was fixed" under this one. Read this.
  column "occurrences" {
    null    = false
    type    = integer
    default = 0
    comment = "runs that reported it failing, not findings; 0 means it never has"
  }
  column "target_id" {
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
    columns = [column.id]
  }

  foreign_key "finding_states_resource_id_fkey" {
    columns     = [column.resource_id]
    ref_columns = [table.resources.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }
  // The evidence cascades away with its scan; the ledger must not. SET NULL
  // rather than no foreign key, because a dangling id that resolves to nothing
  // is worse than an honest absence.
  foreign_key "finding_states_finding_id_fkey" {
    columns     = [column.finding_id]
    ref_columns = [table.findings.column.id]
    on_update   = NO_ACTION
    on_delete   = SET_NULL
  }

  // Structural invariants only, the same line resources.hcl draws: the
  // vocabularies in `status` and `reason` stay unconstrained because
  // 012_drop_enum_constraints.sql removed six such checks and migrate_test
  // asserts they stay gone.
  //
  // Write-once, deliberately. commons-db diffs a check by name and compares only
  // NO INHERIT, never the expression, so editing one of these in place would be
  // silently ignored on every database that already has it. Revising one means a
  // colocated DROP CONSTRAINT / ADD CONSTRAINT script, as 011 and 015 do.
  check "finding_states_seen_order" {
    expr = "last_seen >= first_seen"
  }
  check "finding_states_occurrences_sane" {
    expr = "occurrences >= 0"
  }

  index "finding_states_key" {
    unique  = true
    columns = [column.resource_id, column.engine, column.check_id]
  }
  index "finding_states_resource_idx" {
    columns = [column.resource_id, column.status]
  }
  index "finding_states_check_idx" {
    columns = [column.engine, column.check_id, column.status]
  }
  index "finding_states_last_scan_idx" {
    columns = [column.last_scan_id]
  }
  // Deleting or narrowing a rule reopens what it was suppressing, which is a
  // lookup by rule name.
  index "finding_states_muted_by_idx" {
    columns = [column.muted_by]
  }
  // "Everything open, worst first" is the question the dashboard opens with and
  // the only one with no index behind it: finding_states_check_idx leads with
  // the engine, so a query that names neither engine nor check could not use it.
  index "finding_states_status_idx" {
    columns = [column.status, column.severity]
  }
  // `last_seen` documents itself as the thing a stale state is found by — "a
  // stale value means nobody re-checked" — which is a range scan.
  index "finding_states_last_seen_idx" {
    columns = [column.last_seen]
  }
}
