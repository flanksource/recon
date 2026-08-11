-- phase: post
-- dependsOn: 012_drop_enum_constraints.sql
UPDATE scans
SET duration_ms = GREATEST(
  0,
  FLOOR(EXTRACT(EPOCH FROM (finished_at - started_at)) * 1000)::bigint
)
WHERE finished_at IS NOT NULL
  AND duration_ms = 0;
