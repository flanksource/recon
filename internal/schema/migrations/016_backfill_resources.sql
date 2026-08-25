-- phase: post
-- dependsOn: 015_provider_context_targets.sql
--
-- Recover the estate from the evidence already stored.
--
-- A Resources tab that starts empty on a database holding months of scans reads
-- as broken, and the information is not actually missing: every prowler finding
-- carries the whole OCSF record in `raw`, including the `resources` array and
-- `cloud.account` that the ingest path now reads. This reconstructs what those
-- runs would have recorded had they been run today.
--
-- Restricted to prowler. Reconstructing a resource from trivy's MatchedAt
-- ("Dockerfile:2") or nuclei's is exactly the inference this design exists to
-- forbid — those engines name a location inside a subject, not a subject — so
-- their findings keep a NULL resource_id until a new run emits resources
-- explicitly.
--
-- finding_states is deliberately NOT backfilled. Historic PASS records were
-- counted and discarded, so a backfilled `open` row would have no evidence it is
-- still failing and no pass anywhere that could ever resolve it: permanently
-- stale open rows, which is the precise failure mode this whole feature removes.
-- The first post-upgrade run establishes the ledger correctly and completely.
--
-- `raw` no longer exists once 023 has run: findings became OCSF Detection
-- Findings and the verbatim engine record went with them. This script is a post
-- script, and the phase order is all-pre, diff, all-post — so on any database
-- that had not already applied it, the column it reads from is dropped before it
-- gets to run, and it recovers nothing.
--
-- That is a no-op rather than a loss. The recovery was only ever a convenience so
-- the Resources tab would not read as broken on a database holding old scans; as
-- the paragraph above says, the first post-upgrade run records the estate
-- properly. The guard makes the no-op explicit instead of a failed migration.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'findings' AND column_name = 'raw'
  ) THEN
    RETURN;
  END IF;

  EXECUTE $sql$
INSERT INTO resources (
    provider, scope, uid, kind, type, name, service, region,
    engines, target_id, state, first_seen, last_seen, first_scan_id, last_scan_id
)
SELECT
    recovered.provider,
    recovered.scope,
    recovered.uid,
    -- The same collapse the engine applies: prowler names the project itself
    -- when a check has nothing more specific to point at, typing it with
    -- whichever service the check belongs to, so one project would otherwise
    -- arrive as four differently-typed rows.
    CASE WHEN recovered.uid = recovered.scope THEN 'account' ELSE 'cloud-resource' END,
    CASE WHEN recovered.uid = recovered.scope THEN '' ELSE COALESCE(recovered.type, '') END,
    COALESCE(recovered.name, ''),
    COALESCE(recovered.service, ''),
    COALESCE(recovered.region, ''),
    ARRAY['prowler'],
    recovered.target_id,
    -- Never 'absent'. Absence is a judgement only a run entitled to make it may
    -- write, and a backfill has observed nothing.
    'present',
    recovered.first_seen,
    recovered.last_seen,
    recovered.first_scan_id,
    recovered.last_scan_id
FROM (
    SELECT DISTINCT ON (provider, scope, uid)
        provider, scope, uid, type, name, service, region, target_id,
        MIN(seen) OVER (PARTITION BY provider, scope, uid) AS first_seen,
        MAX(seen) OVER (PARTITION BY provider, scope, uid) AS last_seen,
        FIRST_VALUE(scan_id) OVER (
            PARTITION BY provider, scope, uid ORDER BY seen ASC) AS first_scan_id,
        FIRST_VALUE(scan_id) OVER (
            PARTITION BY provider, scope, uid ORDER BY seen DESC) AS last_scan_id
    FROM (
        SELECT
            COALESCE(NULLIF(f.raw -> 'cloud' ->> 'provider', ''), 'gcp') AS provider,
            COALESCE(f.raw -> 'cloud' -> 'account' ->> 'uid', f.host, '') AS scope,
            resource ->> 'uid' AS uid,
            resource ->> 'type' AS type,
            resource ->> 'name' AS name,
            resource -> 'group' ->> 'name' AS service,
            resource ->> 'region' AS region,
            f.target_id,
            f.scan_id,
            COALESCE(f.timestamp, s.started_at) AS seen
        FROM findings f
        JOIN scans s ON s.id = f.scan_id
        CROSS JOIN LATERAL jsonb_array_elements(f.raw -> 'resources') AS resource
        WHERE f.type = 'prowler'
          AND jsonb_typeof(f.raw -> 'resources') = 'array'
          -- A resource with no uid cannot be addressed, and inserting one would
          -- collide with every other uid-less row on the unique key.
          AND COALESCE(resource ->> 'uid', '') <> ''
    ) named
    -- Newest wins for the last-writer attributes, which is what the upsert does.
    ORDER BY provider, scope, uid, seen DESC
) recovered
ON CONFLICT (provider, scope, uid) DO NOTHING
  $sql$;

  -- Link the evidence to what it was about. Only the first resource of each
  -- record: a check's verdict is about one subject and the rest are context, and
  -- fanning it across all of them is what would let one verdict resolve findings
  -- on things the check never judged.
  EXECUTE $sql$
UPDATE findings f
SET resource_id = r.id
FROM resources r
WHERE f.resource_id IS NULL
  AND f.type = 'prowler'
  AND jsonb_typeof(f.raw -> 'resources') = 'array'
  AND r.uid = f.raw -> 'resources' -> 0 ->> 'uid'
  AND r.scope = COALESCE(f.raw -> 'cloud' -> 'account' ->> 'uid', f.host, '')
  AND r.provider = COALESCE(NULLIF(f.raw -> 'cloud' ->> 'provider', ''), 'gcp')
  $sql$;
END $$;
