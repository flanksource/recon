table "scan_schedules" {
  schema = schema.public
  column "id" {
    type = uuid
    null = false
    default = sql("generate_ulid()")
  }
  column "name" {
    type = text
    null = false
  }
  column "enabled" {
    type = boolean
    null = false
    default = true
  }
  column "engine" {
    type = text
    null = false
  }
  column "profile" {
    type = text
    null = false
  }
  column "targets" {
    type = jsonb
    null = false
  }
  column "cron" {
    type = text
    null = false
  }
  column "timezone" {
    type = text
    null = false
    default = "UTC"
  }
  column "confirm" {
    type = boolean
    null = false
    default = false
  }
  column "next_run" {
    type = timestamptz
    null = true
  }
  column "last_run" {
    type = timestamptz
    null = true
  }
  column "last_error" {
    type = text
    null = false
    default = ""
  }
  column "created_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  column "updated_at" {
    type = timestamptz
    null = false
    default = sql("now()")
  }
  column "deleted_at" {
    type = timestamptz
    null = true
  }
  primary_key {
    columns = [column.name]
  }
  index "scan_schedules_id_key" {
    unique = true
    columns = [column.id]
  }
  check "scan_schedules_name_format" {
    expr = "name ~ '^[a-z0-9][a-z0-9-]*$'"
  }
  index "scan_schedules_due_idx" {
    columns = [column.next_run]
    where = "enabled"
  }
}
