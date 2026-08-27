-- phase: post
-- dependsOn: 023_ocsf_findings.sql
--
-- Stored mute expressions move onto the OCSF vocabulary.
--
-- A rule's `expr` is CEL over one `finding` variable, and that variable is the
-- finding's own JSON projection — so reshaping the record reshaped the
-- expression vocabulary with it. Every rewrite below is one-to-one: the path
-- changes name and addresses the identical value.
--
-- Everything that is not one-to-one is refused rather than guessed at. A
-- suppression that quietly stops matching hides nothing and looks exactly like
-- one that correctly matched nothing, so the failure has to be at upgrade time
-- and by name.
--
-- Runs in the post phase: mute_rules is created by the declarative diff, and on
-- a blank database there is nothing to rewrite.
DO $$
DECLARE
  rename  record;
  stale   text;
BEGIN
  IF to_regclass('mute_rules') IS NULL THEN
    RETURN;
  END IF;

  -- `raw.info` is the one prefix whose keys did not survive as a group: three
  -- of them became modelled attributes and 023 deleted the rest along with the
  -- object. Translating the three first means the check below sees only the
  -- ones that have nowhere to go.
  FOR rename IN
    SELECT * FROM (VALUES
      ('finding\.raw\.info\.description\M',  'finding.finding_info.desc'),
      ('finding\.raw\.info\.name\M',         'finding.finding_info.title'),
      ('finding\.raw\.info\.reference\M',    'finding.finding_info.src_url'),
      ('finding\.raw\.resources\M',          'finding.resources'),
      ('finding\.raw\.cloud\M',              'finding.cloud'),
      ('finding\.raw\.unmapped\M',           'finding.unmapped'),
      ('finding\.templateId\M',              'finding.checkId'),
      ('finding\.type\M',                    'finding.engine'),
      ('finding\.name\M',                    'finding.finding_info.title'),
      ('finding\.reference\M',               'finding.remediation.references'),
      -- Guarded against itself: `remediation` gained a level rather than a new
      -- name, so a second pass over an already-rewritten rule would otherwise
      -- append a second `.desc`.
      ('finding\.remediation\M(?!\.(desc|references)\M)', 'finding.remediation.desc')
    ) AS t(pattern, replacement)
  LOOP
    UPDATE mute_rules
    SET expr = regexp_replace(expr, rename.pattern, rename.replacement, 'g')
    WHERE expr ~ rename.pattern;
  END LOOP;

  -- What no rewrite can honestly do:
  --
  --   raw.<anything else>  the engine's leftovers are in `unmapped` now, but
  --                        only for rows this upgrade converted — an adapter
  --                        chooses what it puts there, so the paths are not the
  --                        same set and rewriting would produce a rule that
  --                        matches history and nothing since.
  --   severity             a string became severity_id, an integer.
  --   timestamp            an RFC3339 string became `time`, epoch millis.
  --   matcherName          four engines wrote four meanings into it; each has
  --                        its own home now and no single path replaces it.
  --   request/response/    one column each became one entry in evidences[], so
  --   curl/extracted       reading them is a comprehension, not a path.
  SELECT string_agg(format('  %s: %s', name, expr), E'\n' ORDER BY name)
  INTO stale
  FROM mute_rules
  WHERE expr ~ ('finding\.raw\M|finding\.severity\M|finding\.timestamp\M'
                '|finding\.matcherName\M|finding\.request\M|finding\.response\M'
                '|finding\.curl\M|finding\.extracted\M');

  IF stale IS NOT NULL THEN
    RAISE EXCEPTION E'mute rules address fields that findings no longer have:\n%\n\n'
      'Findings are OCSF Detection Findings now. Rewrite each expression against '
      'the new vocabulary — severity_id (integer) for severity, time (epoch millis) '
      'for timestamp, unmapped.* for what the engine reported that the schema does '
      'not name, and evidences[] for the request, response, curl and extracted '
      'values — then re-run the migration. To park one instead: '
      'UPDATE mute_rules SET disabled = true, expr = NULL WHERE name = ''<name>'';',
      stale;
  END IF;
END $$;
