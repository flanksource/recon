-- phase: post
-- The declarative phase adds the unclassified class first and suppresses the
-- legacy table drop; only then can its rows be moved without data loss.
DO $$
BEGIN
  IF to_regclass('public.discovery_unknown_hosts') IS NOT NULL THEN
    INSERT INTO targets (host, class, source, profiles, tags, created_at, updated_at)
    SELECT host, 'unclassified', 'discovery', ARRAY['safe']::text[], '{}'::text[], first_seen, last_seen
    FROM discovery_unknown_hosts
    ON CONFLICT (host) DO NOTHING;

    DROP TABLE discovery_unknown_hosts;
  END IF;
END
$$;
