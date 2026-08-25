-- phase: post
-- dependsOn: 016_backfill_resources.sql
--
-- Recover the check catalogue from the evidence already stored.
--
-- Every finding carries its own check's description, so nothing is missing —
-- it is only that it lived nowhere a resolved or pruned finding could reach it.
-- Without this the catalogue would start empty and stay that way for any check
-- no new run happens to report, which is exactly the long-resolved checks whose
-- history a person is most likely to be reading.
--
-- Newest wins, matching the upsert the ingest path performs: a check whose title
-- was reworded upstream should read the new way everywhere.
--
-- Reads the OCSF columns, which is where the description lives now: the title is
-- finding_info.title, the severity is OCSF's integer scale, and remediation is
-- one object rather than a text column beside a references array. 023 populates
-- all of them in the pre phase, so they are present by the time this runs —
-- including on a database old enough never to have run this script before.
--
-- The projections are deliberately the same ones upsertChecksSQL applies on the
-- live path (store/checks.go): a check recovered here and a check recorded by
-- the next run must describe itself identically, or the catalogue would change
-- under the reader the first time a scan touched it.
INSERT INTO checks (
    engine, check_id, name, severity, type, remediation, reference, tags,
    first_seen, last_seen
)
SELECT DISTINCT ON (recovered.engine, recovered.check_id)
    recovered.engine,
    recovered.check_id,
    COALESCE(recovered.name, ''),
    COALESCE(NULLIF(recovered.severity, ''), 'unknown'),
    recovered.type,
    recovered.remediation,
    COALESCE(recovered.reference, '{}'::text[]),
    COALESCE(recovered.tags, '{}'::text[]),
    recovered.first_seen,
    recovered.last_seen
FROM (
    SELECT
        s.engine,
        f.check_id,
        COALESCE(f.finding_info ->> 'title', f.check_id) AS name,
        CASE f.severity_id
            WHEN 6 THEN 'critical'
            WHEN 5 THEN 'critical'
            WHEN 4 THEN 'high'
            WHEN 3 THEN 'medium'
            WHEN 2 THEN 'low'
            WHEN 1 THEN 'info'
            ELSE 'unknown'
        END AS severity,
        -- checks.type records which engine owns the check, which is what the
        -- findings column of that name always held.
        f.engine AS type,
        f.remediation ->> 'desc' AS remediation,
        ARRAY(SELECT jsonb_array_elements_text(f.remediation -> 'references')) AS reference,
        f.tags,
        MIN(COALESCE(f."time", s.started_at)) OVER (
            PARTITION BY s.engine, f.check_id) AS first_seen,
        MAX(COALESCE(f."time", s.started_at)) OVER (
            PARTITION BY s.engine, f.check_id) AS last_seen,
        COALESCE(f."time", s.started_at) AS seen
    FROM findings f
    JOIN scans s ON s.id = f.scan_id
    WHERE COALESCE(f.check_id, '') <> ''
) recovered
ORDER BY recovered.engine, recovered.check_id, recovered.seen DESC
ON CONFLICT (engine, check_id) DO NOTHING;
