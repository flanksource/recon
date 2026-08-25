-- phase: pre
-- dependsOn: 015_provider_context_targets.sql
--
-- One resource, every engine that has described it.
--
-- `resources` is keyed on (provider, scope, uid) and deliberately not on the
-- engine, so a resource two engines both describe is one row — and the scalar
-- `engine` column was therefore whichever engine finalized last. The absence
-- sweep reads that column to decide whose view it is entitled to judge
-- (markAbsentSQL), so a resource prowler and trivy both saw became invisible to
-- whichever of them ran first: it stayed `present` for ever, and its findings
-- closed as `not-reported` rather than `resource-absent`.
--
-- Added here, before the Atlas diff drops `engine`, so the attribution carries
-- across instead of every existing row starting empty.
ALTER TABLE IF EXISTS resources
  ADD COLUMN IF NOT EXISTS engines text[] NOT NULL DEFAULT '{}'::text[];

-- Dynamic, because on a blank database Atlas has not created the table yet and
-- a static reference to the old column would fail to parse.
DO $$
BEGIN
  IF to_regclass('resources') IS NULL THEN
    RETURN;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'resources' AND column_name = 'engine'
  ) THEN
    RETURN;
  END IF;

  -- Only where nothing has been recorded yet: re-running this must not undo a
  -- union a later scan has already widened.
  EXECUTE $backfill$
    UPDATE resources
    SET engines = ARRAY[engine]
    WHERE engine <> '' AND cardinality(engines) = 0
  $backfill$;
END $$;
