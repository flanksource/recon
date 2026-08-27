// The things checks run against.
//
// A resource outlives every run that looked at it, which is why it is a row and
// not a column on a finding. Recording one for a check that passed is the point:
// a compliance scan of two GCP projects reports 190 verdicts naming 94
// resources, and keeping only the 49 that failed left half the estate invisible
// and "is this bucket clean" unanswerable.
//
// The typed columns are what selectors filter on and the jsonb ones are what the
// provider happened to say — the same division targets.hcl draws, and for the
// same reason: modelling a provider's own document as columns would turn every
// upstream field addition into a migration.
table "resources" {
  schema = schema.public

  column "id" {
    null    = false
    type    = uuid
    default = sql("generate_ulid()")
  }

  // The natural key. All three are NOT NULL with an empty default rather than
  // nullable, because a unique index treats NULLs as distinct: a nullable scope
  // would stop ON CONFLICT ever firing and every scan would insert the estate
  // again.
  column "provider" {
    null = false
    type = text
  }
  column "scope" {
    null    = false
    type    = text
    default = ""
    comment = "the account, project or registry that makes uid unique; `default` is a VPC in every GCP project"
  }
  column "uid" {
    null    = false
    type    = text
    comment = "the provider's own identifier, frequently opaque: a GCP firewall's is a number"
  }

  column "kind" {
    null    = false
    type    = text
    comment = "account | cloud-resource | artifact | endpoint"
  }
  // Descriptive, never identity. Prowler synthesises a per-service resource for
  // an account-level check, so one project id arrives typed four different ways
  // in a single run; keying on type would mint four rows for one project.
  column "type" {
    null    = false
    type    = text
    default = ""
  }
  column "name" {
    null    = false
    type    = text
    default = ""
    comment = "human-readable; uid is the fallback at read time, not the default"
  }
  column "service" {
    null    = false
    type    = text
    default = ""
  }
  column "region" {
    null    = false
    type    = text
    default = ""
    comment = "verbatim: global, europe-west1, eu, US, eur5"
  }

  column "account_name" {
    null    = false
    type    = text
    default = ""
  }
  column "org_uid" {
    null    = false
    type    = text
    default = ""
  }
  column "org_name" {
    null    = false
    type    = text
    default = ""
  }
  // Every engine that has described this resource, not the last one to.
  //
  // The identity above deliberately excludes the engine, so one row serves all
  // of them — and a scalar column here was therefore last-writer-wins. That
  // silently broke the invariant it exists to state: a resource trivy described
  // after prowler did carried `trivy`, so prowler's absence sweep skipped it
  // for good and its findings closed as `not-reported` rather than
  // `resource-absent`.
  column "engines" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
    comment = "which engines describe this resource; absence is only ever judged within one engine's own view"
  }
  column "target_id" {
    null    = true
    type    = text
    comment = "last inventory target that reached it; no foreign key so resource history survives target deletion"
  }

  // What Mission Control's catalog would know the same thing as. Derived at
  // ingest and stored so a lookup never recomputes it, and empty wherever recon
  // cannot say — a wrong type scopes a catalog search to rows that cannot match,
  // which turns a miss into a confident mismatch.
  column "config_type" {
    null    = false
    type    = text
    default = ""
    comment = "config-db config item type, e.g. GCP::Firewall"
  }
  column "external_ids" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
    comment = "lowercased identities config-db could hold, offered together because no single field is reliably its primary one"
  }

  // Where a person said this resource's insights belong, when its identity named
  // more than one config item and the ladder could not decide. Written by a sync
  // that actually pushed and never by an engine — the upsert above deliberately
  // leaves both columns alone — so a re-scan cannot undo a decision.
  //
  // No foreign key: the catalog lives in another database entirely. A choice
  // that has since been deleted upstream is reported as unresolved at sync time
  // rather than silently pushed against a dangling id.
  column "config_id" {
    null    = true
    type    = uuid
    comment = "chosen Mission Control config item; NULL until somebody chooses"
  }
  column "config_rolled_up" {
    null    = false
    type    = boolean
    default = false
    comment = "the chosen item contains this resource rather than being it"
  }

  column "tags" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }
  column "labels" {
    null    = true
    type    = jsonb
  }
  column "metadata" {
    null    = true
    type    = jsonb
    comment = "the provider's own document, verbatim"
  }

  column "state" {
    null    = false
    type    = text
    default = "present"
    comment = "present | absent; absent is only ever written by a run entitled to say so"
  }
  // When it stopped being there, which last_seen cannot answer: that is the last
  // time a run saw it, and the gap between the two is how long nobody noticed.
  column "absent_at" {
    null    = true
    type    = timestamptz
    comment = "when a covering run first failed to see it; NULL while present"
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
  column "first_scan_id" {
    null = true
    type = uuid
  }
  column "last_scan_id" {
    null    = true
    type    = uuid
    comment = "no foreign key: pruning a run must not delete the estate it described"
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

  // Structural only. Application vocabularies — kind, state, type, region — are
  // deliberately unconstrained: 012_drop_enum_constraints.sql removed six such
  // checks and migrate_test asserts they stay gone, and `eur5` is exactly the
  // region a hand-written enum would have omitted.
  check "resources_uid_present" {
    expr = "uid <> ''"
  }
  check "resources_provider_format" {
    expr = "provider ~ '^[a-z0-9][a-z0-9-]*$'"
  }
  check "resources_seen_order" {
    expr = "last_seen >= first_seen"
  }

  index "resources_identity_key" {
    unique  = true
    columns = [column.provider, column.scope, column.uid]
  }
  index "resources_scope_idx" {
    columns = [column.provider, column.scope]
  }
  index "resources_target_idx" {
    columns = [column.target_id]
  }
  index "resources_kind_idx" {
    columns = [column.kind]
  }
  index "resources_type_idx" {
    columns = [column.type]
  }
  index "resources_service_idx" {
    columns = [column.service]
  }
  index "resources_region_idx" {
    columns = [column.region]
  }
  index "resources_state_idx" {
    columns = [column.state]
  }
  index "resources_last_seen_idx" {
    columns = [column.last_seen]
  }
  index "resources_config_type_idx" {
    columns = [column.config_type]
  }
  index "resources_tags_idx" {
    type    = GIN
    columns = [column.tags]
  }
  // The absence sweep asks "is this engine one of them", which is a containment
  // test over an array and so the same shape as tags and external_ids.
  index "resources_engines_idx" {
    type    = GIN
    columns = [column.engines]
  }
  index "resources_labels_idx" {
    type    = GIN
    columns = [column.labels]
  }
  // The catalog lookup is an array-containment test, which is what a GIN index
  // over text[] answers. No index on metadata: nothing filters on it, it is the
  // largest column here, and a GIN over it would be pure write cost.
  index "resources_external_ids_idx" {
    type    = GIN
    columns = [column.external_ids]
  }
}
