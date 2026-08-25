-- phase: pre
-- dependsOn: 017_resource_engines.sql
--
-- Repair before constraining.
--
-- finding_states is about to gain finding_states_seen_order and
-- finding_states_occurrences_sane. Postgres validates a CHECK against existing
-- rows when it is added, so a single row left over from before the ledger had a
-- monotonicity guard would fail the migration and take every later change with
-- it — on exactly the long-lived databases the constraints are meant to protect.
--
-- Both repairs are conservative: they move the derived value to the one the
-- other columns already imply, never the other way round.
DO $$
BEGIN
  IF to_regclass('finding_states') IS NULL THEN
    RETURN;
  END IF;

  -- An out-of-order run used to be able to write a last_seen behind first_seen.
  -- first_seen is the one with independent meaning — the first verdict of any
  -- kind — so last_seen moves up to meet it.
  UPDATE finding_states SET last_seen = first_seen WHERE last_seen < first_seen;

  UPDATE finding_states SET occurrences = 0 WHERE occurrences < 0;
END $$;
