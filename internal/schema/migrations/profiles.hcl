// Engine profiles, keyed by (kind, engine, name) so a discovery httpx profile
// and a scan httpx profile can share a name without colliding.
//
// `config` is jsonb: it is validated against the engine's own option catalog in
// Go, not by the database, and its keys change whenever the upstream tool adds
// a flag.
table "engine_profiles" {
  schema = schema.public

  column "kind" {
    null = false
    type = text
  }
  column "engine" {
    null = false
    type = text
  }
  column "name" {
    null = false
    type = text
  }
  column "config" {
    null    = false
    type    = jsonb
    default = sql("'{}'::jsonb")
  }

  // The leading `#` block from the YAML the profile was imported from. The
  // TypeScript writer preserved it on every save; keeping it means a rendered
  // profile still explains itself to whoever reads the generated file.
  column "comment" {
    null = true
    type = text
  }

  // Extra input files an engine consumes alongside its config — the safe paths
  // httpx probes, today.
  column "paths" {
    null = true
    type = sql("text[]")
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
    columns = [column.kind, column.engine, column.name]
  }

  // Mirrors the rule the TypeScript profile store enforced, so a profile name is
  // always safe to use as a filename fragment.
  check "engine_profiles_name_format" {
    expr = "name ~ '^[a-z0-9][a-z0-9-]*$'"
  }

  index "engine_profiles_engine_idx" {
    columns = [column.engine]
  }
}
