-- phase: post
-- dependsOn: 019_mute_attribution.sql
--
-- What kind of verdict a finding is, in recon's vocabulary rather than an
-- engine's.
--
-- The lifecycle read `matcher_name = 'MANUAL'` to decide a state was one a human
-- still owes a decision on. That worked only because prowler writes its OCSF
-- status_code into a column nuclei means as the matcher that fired: two engines,
-- one column, two meanings, and any engine that ever named a matcher MANUAL
-- would have minted manual states from it.
--
-- The existing rows already carry the answer in the old place, so read it across
-- once. Everything else is a plain failure, which is what it always was.
--
-- That old place is now status_code, where the value belonged all along: 023
-- moves it there in the pre phase, before the diff drops matcher_name. Reading
-- the new column rather than guarding on the old one is what lets this script
-- keep working on every database — a fresh one, one that already ran it, and one
-- old enough to reach the drop and the recovery in a single migration.
UPDATE findings
SET verdict = 'manual'
WHERE verdict = 'fail'
  AND status_code = 'MANUAL'
  AND engine = 'prowler';
