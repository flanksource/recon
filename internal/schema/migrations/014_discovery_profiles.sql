-- phase: pre
-- A sweep now records the profile each engine ran with rather than one name for
-- all of them. The column is added here, before the Atlas diff drops `profile`,
-- so the history carries across: which engines a past run used is recoverable
-- from the rows those engines wrote.
ALTER TABLE IF EXISTS discoveries
  ADD COLUMN IF NOT EXISTS profiles jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Dynamic, because on a blank database Atlas has not created the table yet and
-- a static reference to the old column would fail to parse.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = current_schema() AND table_name = 'discoveries' AND column_name = 'profile'
  ) THEN
    EXECUTE $backfill$
      UPDATE discoveries d
      SET profiles = COALESCE((
        SELECT jsonb_object_agg(h.engine, d.profile)
        FROM discovery_hosts h
        WHERE h.discovery_id = d.id
      ), '{}'::jsonb)
      WHERE d.profiles = '{}'::jsonb
    $backfill$;
  END IF;
END $$;
