-- phase: post
-- dependsOn: 023_ocsf_findings.sql
--
-- Repairs what the first shipped 023 got wrong.
--
-- Two things. It derived `engine` from the old column named `type`, which is the
-- very conflation this redesign exists to delete: prowler and trivy wrote their
-- engine name into it, nuclei wrote the protocol a template spoke. So every
-- nuclei finding came out of the upgrade labelled "dns" or "http", or NULL when
-- the host never answered — and a whole run showed an empty Engine column.
--
-- And it moved everything `raw` held into `unmapped`, including every attribute
-- that had just been given a column of its own. That is not a migration to OCSF;
-- it is the verbatim copy under a new name — prowler's whole record stored
-- twice, and trivy's `Match`, the masked secret its adapter refuses to carry,
-- carried anyway.
--
-- 023 is fixed too, for a database that has not upgraded yet. It cannot repair
-- one that has: its backfills are guarded on the new columns still being NULL,
-- which is what makes it safe to re-run, and they are not NULL any more. Hence
-- this, which is written as an invariant rather than a backfill and is therefore
-- a no-op everywhere it has already held.
DO $$
DECLARE
  -- The only keys an adapter puts in the escape hatch, which is what a migrated
  -- row must end up carrying too. nuclei writes these three; prowler writes
  -- categories and compliance; trivy and inspec write nothing.
  --
  -- prowler's two cannot be recovered here — 023 dropped raw.unmapped before the
  -- column went away — so its rows end up empty rather than wrong. A re-scan
  -- restores them, and the same is true of nuclei's authors.
  keep text[] := ARRAY['protocol', 'matcher_name', 'authors',
                       'categories', 'compliance'];
BEGIN
  IF to_regclass('findings') IS NULL OR to_regclass('scans') IS NULL THEN
    RETURN;
  END IF;

  -- A scan runs one engine, so a finding's engine is its scan's engine. There
  -- is no case where the two legitimately differ.
  EXECUTE $sql$
    UPDATE findings f SET engine = s.engine
    FROM scans s
    WHERE s.id = f.scan_id
      AND COALESCE(s.engine, '') <> ''
      AND f.engine IS DISTINCT FROM s.engine
  $sql$;

  -- Rename before pruning, or the two nuclei keys are pruned as strangers: the
  -- raw record calls the protocol `type` — the word the old column used for the
  -- engine — and its matcher `matcher-name`, and one fact spelled two ways is
  -- one no expression can read.
  EXECUTE $sql$
    UPDATE findings SET unmapped =
      (unmapped - 'type') || jsonb_build_object('protocol', unmapped ->> 'type')
    WHERE engine = 'nuclei'
      AND unmapped ? 'type'
      AND NOT unmapped ? 'protocol'
      AND COALESCE(unmapped ->> 'type', '') <> ''
  $sql$;

  EXECUTE $sql$
    UPDATE findings SET unmapped =
      (unmapped - 'matcher-name')
      || jsonb_build_object('matcher_name', unmapped ->> 'matcher-name')
    WHERE unmapped ? 'matcher-name'
      AND NOT unmapped ? 'matcher_name'
      AND COALESCE(unmapped ->> 'matcher-name', '') <> ''
  $sql$;

  -- The escape hatch stops being a second copy of the record. Everything else
  -- the engine said is in the run's retained artifact.
  EXECUTE $sql$
    UPDATE findings SET unmapped = NULLIF(
      (SELECT COALESCE(jsonb_object_agg(key, value), '{}'::jsonb)
       FROM jsonb_each(unmapped) WHERE key = ANY($1)), '{}'::jsonb)
    WHERE unmapped IS NOT NULL
      AND EXISTS (SELECT 1 FROM jsonb_each(unmapped) WHERE key <> ALL($1))
  $sql$ USING keep;

  -- src_url is one link. nuclei writes info.reference as an array, and 023 read
  -- it with ->>, which renders a whole JSON array as text — so the field the
  -- schema types as a URL held `["https://a", "https://b"]` verbatim.
  EXECUTE $sql$
    UPDATE findings SET finding_info =
      jsonb_set(finding_info, '{src_url}',
                to_jsonb((finding_info ->> 'src_url')::jsonb ->> 0))
    WHERE finding_info ->> 'src_url' ~ '^\[\s*"'
  $sql$;

  -- An array that held nothing usable leaves no link at all rather than a null
  -- one, which is what jsonb_set above would write.
  EXECUTE $sql$
    UPDATE findings SET finding_info = finding_info - 'src_url'
    WHERE finding_info -> 'src_url' = 'null'::jsonb
  $sql$;
END $$;
