-- phase: pre
-- dependsOn: 020_finding_state_invariants.sql
--
-- Every subject an already-recorded finding named, moved out of the raw blob
-- and into a relation.
--
-- A check that fails against forty buckets names forty, and only the first was
-- ever linked. The rest lived in `raw` alone — engine-specific, unqueryable, and
-- on its way out. This recovers them while it is still there to recover from,
-- which is why it runs in the pre phase: the Atlas diff drops `raw`, and a post
-- script would be reading a column that no longer exists.
--
-- The table is created here rather than waited for, because the diff that
-- creates it runs after this script. Atlas sees it already present and leaves it
-- alone; the definition is kept identical to the one in scans.hcl.
CREATE TABLE IF NOT EXISTS finding_resources (
  finding_id  uuid    NOT NULL,
  resource_id uuid    NOT NULL,
  ordinal     integer NOT NULL,
  PRIMARY KEY (finding_id, resource_id)
);

DO $$
BEGIN
  IF to_regclass('finding_resources') IS NULL OR to_regclass('findings') IS NULL THEN
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE table_name = 'finding_resources'
      AND constraint_name = 'finding_resources_finding_id_fkey'
  ) THEN
    ALTER TABLE finding_resources
      ADD CONSTRAINT finding_resources_finding_id_fkey
      FOREIGN KEY (finding_id) REFERENCES findings (id) ON DELETE CASCADE;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM information_schema.table_constraints
    WHERE table_name = 'finding_resources'
      AND constraint_name = 'finding_resources_resource_id_fkey'
  ) THEN
    ALTER TABLE finding_resources
      ADD CONSTRAINT finding_resources_resource_id_fkey
      FOREIGN KEY (resource_id) REFERENCES resources (id) ON DELETE CASCADE;
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS finding_resources_resource_idx
  ON finding_resources (resource_id);

-- Prowler's OCSF records, whose `resources` array names the subjects.
--
-- The join is on the full natural key, which the record does not carry per
-- resource: OCSF 1.5.0 puts the account once at the event level, so provider and
-- scope are read from `cloud`/`unmapped` and applied to every entry. That is
-- exactly the identity the ingest path builds, so a row recovered here and a row
-- written today are keyed the same way.
--
-- WITH ORDINALITY preserves the position the record named each subject in, which
-- decides which one the verdict is about. It is 1-based, so it is shifted to
-- match the 0-based ordinals the writer uses.
--
-- Dynamic, because on a blank database `raw` has already been replaced and a
-- static reference to it would fail to parse.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'findings' AND column_name = 'raw'
  ) THEN
    RETURN;
  END IF;

  EXECUTE $sql$
    INSERT INTO finding_resources (finding_id, resource_id, ordinal)
    SELECT DISTINCT ON (findings.id, resources.id)
           findings.id,
           resources.id,
           (named.position - 1)::integer
    FROM findings
    CROSS JOIN LATERAL jsonb_array_elements(
      CASE
        WHEN jsonb_typeof(findings.raw -> 'resources') = 'array' THEN findings.raw -> 'resources'
        ELSE '[]'::jsonb
      END
    ) WITH ORDINALITY AS named(entry, position)
    JOIN resources
      ON resources.uid = named.entry ->> 'uid'
     AND resources.provider = COALESCE(
           NULLIF(findings.raw -> 'cloud' ->> 'provider', ''),
           NULLIF(findings.raw -> 'unmapped' ->> 'provider', ''),
           '')
     AND resources.scope = COALESCE(
           NULLIF(findings.raw -> 'cloud' -> 'account' ->> 'uid', ''),
           NULLIF(findings.raw -> 'cloud' -> 'account' ->> 'name', ''),
           NULLIF(findings.raw -> 'unmapped' ->> 'provider_uid', ''),
           '')
    WHERE findings.raw IS NOT NULL
      AND COALESCE(named.entry ->> 'uid', '') <> ''
    ORDER BY findings.id, resources.id, named.position
    ON CONFLICT DO NOTHING
  $sql$;
END $$;

-- The canonical subject, for every finding the statement above did not reach.
--
-- nuclei, trivy and inspec name no resources array, so their link exists only as
-- findings.resource_id. Recording it here means one relation answers "what is
-- this finding about" for every engine, rather than callers checking two places.
-- Dynamic for the same reason as above: in the pre phase of a blank database
-- the diff has not created findings yet, and a static reference to it would
-- fail to parse rather than finding nothing to do.
DO $$
BEGIN
  IF to_regclass('findings') IS NULL THEN
    RETURN;
  END IF;
  EXECUTE $sql$
    INSERT INTO finding_resources (finding_id, resource_id, ordinal)
    SELECT findings.id, findings.resource_id, 0
    FROM findings
    WHERE findings.resource_id IS NOT NULL
    ON CONFLICT DO NOTHING
  $sql$;
END $$;
