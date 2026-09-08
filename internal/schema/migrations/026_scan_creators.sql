-- phase: pre
-- dependsOn: 000_ulid.sql
--
-- Preserve the one scan still identified by last_scan before removing it.
-- Older overwritten links cannot be inferred from timing or target selectors.
ALTER TABLE IF EXISTS scans
  ADD COLUMN IF NOT EXISTS creator_user_id text,
  ADD COLUMN IF NOT EXISTS creator_schedule_id uuid;

DO $$
BEGIN
  IF to_regclass('public.scan_schedules') IS NULL THEN
    RETURN;
  END IF;

  ALTER TABLE scan_schedules
    ADD COLUMN IF NOT EXISTS id uuid NOT NULL DEFAULT generate_ulid();

  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'scan_schedules' AND column_name = 'last_scan'
  ) THEN
    UPDATE scans r
    SET creator_schedule_id = s.id
    FROM scan_schedules s
    WHERE r.id::text = s.last_scan
      AND r.creator_user_id IS NULL
      AND r.creator_schedule_id IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM scan_schedules other
        WHERE other.last_scan = s.last_scan AND other.id <> s.id
      );

    ALTER TABLE scan_schedules DROP COLUMN last_scan;
  END IF;
END $$;
