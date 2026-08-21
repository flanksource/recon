-- phase: pre
-- Provider scopes are not hostnames. Give every target a stable identity before
-- making host nullable, and project the two GCP-only kinds onto the generic
-- provider-context representation.
ALTER TABLE IF EXISTS targets ADD COLUMN IF NOT EXISTS id text;
ALTER TABLE IF EXISTS targets ADD COLUMN IF NOT EXISTS kind text;
ALTER TABLE IF EXISTS targets ADD COLUMN IF NOT EXISTS provider text;
ALTER TABLE IF EXISTS targets ADD COLUMN IF NOT EXISTS credential_mode text;
ALTER TABLE IF EXISTS targets ADD COLUMN IF NOT EXISTS arguments jsonb;
ALTER TABLE IF EXISTS findings ADD COLUMN IF NOT EXISTS target_id text;

DO $$
BEGIN
  IF to_regclass('targets') IS NULL THEN
    RETURN;
  END IF;

  ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_kind;
  ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_cloud_has_no_ports;
  ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_profiles_nonempty;

  UPDATE targets SET kind = 'host' WHERE kind IS NULL OR kind = '';

  UPDATE targets
  SET id = CASE
      WHEN kind = 'gcp-project' THEN 'gcp-project-' || host
      WHEN kind = 'gcp-org' THEN 'gcp-org-' || host
      ELSE host
    END
  WHERE id IS NULL;

  UPDATE targets
  SET provider = 'gcp',
      credential_mode = 'ambient',
      arguments = CASE
        WHEN kind = 'gcp-project' THEN jsonb_build_object('project-ids', jsonb_build_array(host))
        ELSE jsonb_build_object('organization-id', host)
      END,
      kind = 'provider-context',
      host = NULL
  WHERE kind IN ('gcp-project', 'gcp-org');

  UPDATE targets SET arguments = '{}'::jsonb
  WHERE kind = 'provider-context' AND arguments IS NULL;

  IF EXISTS (
    SELECT 1
    FROM targets t, unnest(t.profiles) AS assigned(name)
    WHERE assigned.name NOT LIKE 'scan:%:%'
      AND 1 <> (SELECT count(*) FROM engine_profiles p WHERE p.kind = 'scan' AND p.name = assigned.name)
  ) THEN
    RAISE EXCEPTION 'cannot qualify target profile names: every legacy name must resolve to exactly one scan profile';
  END IF;

  UPDATE targets t
  SET profiles = ARRAY(
    SELECT CASE
      WHEN assigned.name LIKE 'scan:%:%' THEN assigned.name
      ELSE (
        SELECT p.kind || ':' || p.engine || ':' || p.name
        FROM engine_profiles p
        WHERE p.kind = 'scan' AND p.name = assigned.name
      )
    END
    FROM unnest(t.profiles) WITH ORDINALITY AS assigned(name, position)
    ORDER BY assigned.position
  );

  ALTER TABLE targets DROP CONSTRAINT IF EXISTS targets_pkey;
  ALTER TABLE targets ALTER COLUMN id SET NOT NULL;
  ALTER TABLE targets ALTER COLUMN host DROP NOT NULL;
  ALTER TABLE targets ADD CONSTRAINT targets_pkey PRIMARY KEY (id);
  CREATE UNIQUE INDEX IF NOT EXISTS targets_host_unique_idx ON targets(host) WHERE host IS NOT NULL;
END $$;
