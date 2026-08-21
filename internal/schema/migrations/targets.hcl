schema "public" {
}

// One row per inventory target. The curated fields are typed columns: they are small,
// constrained, and every selector filters on them. The six machine-owned
// sections are jsonb, because their shape is dictated by whatever the discovery
// engines emit and changes when those tools release — modelling them as columns
// would turn an httpx upgrade into a migration, and would lose the
// absent-vs-empty distinction the wire format depends on.
table "targets" {
  schema = schema.public

  // Stable inventory identity. A host may keep its address as the id, while a
  // provider context has no address and is named independently of whichever
  // accounts or resources its arguments currently select.
  column "id" {
    null = false
    type = text
  }
  column "host" {
    null = true
    type = text
  }
  column "class" {
    null = false
    type = text
  }
  // What kind of thing this row addresses. A host is something on the network
  // with an address and ports; a provider context is audited through an API.
  // They share this table because they share everything that makes a
  // target a target — curation, classification, tags, profiles, scan history —
  // and differ only in how a scan reaches them.
  //
  // Defaulted rather than nullable: every existing row is a host, and a target
  // whose kind is unknown is one nothing can decide how to scan.
  column "kind" {
    null    = false
    type    = text
    default = "host"
  }
  column "provider" {
    null = true
    type = text
  }
  column "credential_mode" {
    null = true
    type = text
  }
  column "arguments" {
    null = true
    type = jsonb
  }
  column "credentials" {
    null = true
    type = jsonb
  }
  column "app" {
    null = true
    type = text
  }
  column "cluster" {
    null = true
    type = text
  }
  column "source" {
    null = true
    type = text
  }

  column "profiles" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
    comment = "curated scan profiles; the schema requires at least one"
  }
  column "ports" {
    null    = true
    type    = sql("integer[]")
    comment = "curated extra ports; NULL rather than '{}' because the schema sets minItems 1"
  }
  column "tags" {
    null    = false
    type    = sql("text[]")
    default = sql("'{}'::text[]")
  }
  column "notes" {
    null = true
    type = text
  }
  column "reason" {
    null    = true
    type    = text
    comment = "required iff class = 'deactivated'"
  }

  column "observed" {
    null = true
    type = jsonb
  }
  column "network" {
    null = true
    type = jsonb
  }
  column "http" {
    null = true
    type = jsonb
  }
  column "tech" {
    null = true
    type = jsonb
  }
  column "tls" {
    null = true
    type = jsonb
  }
  column "scan" {
    null = true
    type = jsonb
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

  // The host pattern from target.schema.json, plus the traversal guard the
  // TypeScript store applied separately. Enforced here as the last line of
  // defence: the JSON Schema runs first, but nothing outside this database can
  // be trusted to have run it.
  check "targets_host_format" {
    expr = "host IS NULL OR ((host ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' OR host ~ '^[0-9a-f:]+$') AND host !~ '[.][.]')"
  }
  // The allOf if/then pair from the JSON Schema, in its SQL form.
  check "targets_reason_iff_deactivated" {
    expr = "(class = 'deactivated') = (reason IS NOT NULL)"
  }
  // cardinality(), not array_length(): array_length('{}', 1) is NULL rather
  // than 0, and a CHECK passes on NULL, so the obvious spelling silently
  // accepts the empty array the schema's minItems forbids.
  //
  check "targets_profiles_nonempty" {
    expr = "cardinality(profiles) >= 1"
  }
  // A CHECK cannot contain a subquery, so bound the array with quantifiers.
  check "targets_ports_bounded" {
    expr = "ports IS NULL OR (cardinality(ports) >= 1 AND 1 <= ALL (ports) AND 65535 >= ALL (ports))"
  }
  // The kind enum from target.schema.json.
  check "targets_kind" {
    expr = "kind IN ('host', 'provider-context')"
  }
  // A cloud account has no ports, and a port on one would resolve to an
  // endpoint that does not exist — pointing a network scanner at a project id
  // as though it were a hostname.
  check "targets_cloud_has_no_ports" {
    expr = "kind = 'host' OR ports IS NULL"
  }
  check "targets_kind_shape" {
    expr = "(kind = 'host' AND host IS NOT NULL AND provider IS NULL AND credential_mode IS NULL AND arguments IS NULL AND credentials IS NULL) OR (kind = 'provider-context' AND host IS NULL AND provider IS NOT NULL AND credential_mode IN ('ambient', 'configured') AND arguments IS NOT NULL)"
  }
  check "targets_id_format" {
    expr = "id ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' OR id ~ '^[0-9a-f:]+$'"
  }
  check "targets_provider_format" {
    expr = "provider IS NULL OR provider ~ '^[a-z0-9][a-z0-9-]*$'"
  }

  index "targets_host_unique_idx" {
    unique  = true
    columns = [column.host]
    where   = "host IS NOT NULL"
  }

  index "targets_class_idx" {
    columns = [column.class]
  }
  // Every host-facing selector filters on kind, and the cloud accounts are a
  // handful of rows among thousands of hosts, so this is what keeps the common
  // case from scanning the whole table.
  index "targets_kind_idx" {
    columns = [column.kind]
  }
  index "targets_tags_idx" {
    type    = GIN
    columns = [column.tags]
  }
  index "targets_profiles_idx" {
    type    = GIN
    columns = [column.profiles]
  }

  // Expression indexes rather than STORED generated columns: they give the
  // selector the same pushdown for ordering and range filters without Atlas
  // having to diff a generation expression, which it cannot do without a
  // DROP/ADD cycle on the column.
  index "targets_last_seen_idx" {
    on {
      expr = "(observed ->> 'last_seen')"
    }
  }
  index "targets_last_scan_idx" {
    on {
      expr = "(scan ->> 'last_scan')"
    }
  }
  index "targets_status_idx" {
    on {
      expr = "(http ->> 'status_code')"
    }
  }
  index "targets_failure_idx" {
    on {
      expr = "(observed ->> 'failure')"
    }
  }
}

// The DNS zones discovery enumerates. Replaces inventory.json.
table "zones" {
  schema = schema.public

  column "zone" {
    null = false
    type = text
  }
  column "created_at" {
    null    = false
    type    = timestamptz
    default = sql("now()")
  }

  primary_key {
    columns = [column.zone]
  }

  check "zones_format" {
    expr = "zone ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'"
  }
}
