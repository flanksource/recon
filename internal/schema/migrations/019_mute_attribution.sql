-- phase: post
-- dependsOn: 018_check_catalogue.sql
--
-- Which rule accepted a finding, as a value rather than a substring.
--
-- The attribution was already there, spelled `mute:<name>` inside `reason`, and
-- reading it back meant a LIKE over a free-text column that also holds
-- `passed`, `not-reported` and `resource-absent`. Deleting a rule now reopens
-- what it suppressed, and that is a keyed update — so the existing rows need the
-- key they were always describing.
UPDATE finding_states
SET muted_by = substring(reason FROM 6)
WHERE muted_by IS NULL
  AND status = 'muted'
  AND reason LIKE 'mute:%'
  AND length(reason) > 5;
