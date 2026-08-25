-- phase: pre
-- dependsOn: 022_finding_resources.sql
--
-- Findings become OCSF Detection Findings.
--
-- What a finding was: a nuclei-shaped row with a verbatim copy of the engine's
-- own record beside it in `raw`, unbounded, shipped whole to Mission Control and
-- marshalled into every report. What triage actually needed — a description, an
-- impact, a CVE, the HTTP exchange — was reachable only by digging through that
-- blob, differently per engine.
--
-- What it is now: the record OCSF already defines for exactly this, so the
-- fields have published names and meanings and a consumer that speaks OCSF can
-- read one without knowing anything about recon.
--
-- Runs in the pre phase, before the Atlas diff drops the columns it reads from.

-- `remediation` changes shape rather than name: it was free text beside a
-- `reference` array, and OCSF models the two together as one object. A type
-- change in place is not something the diff can do with rows already in the
-- column, so the old one is moved aside and dropped by the diff afterwards.
DO $$
BEGIN
  IF to_regclass('findings') IS NULL THEN
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'findings' AND column_name = 'remediation' AND data_type = 'text'
  ) THEN
    ALTER TABLE findings RENAME COLUMN remediation TO remediation_text;
  END IF;
END $$;

ALTER TABLE IF EXISTS findings
  ADD COLUMN IF NOT EXISTS remediation jsonb,
  ADD COLUMN IF NOT EXISTS check_id text,
  ADD COLUMN IF NOT EXISTS engine text,
  ADD COLUMN IF NOT EXISTS class_uid integer NOT NULL DEFAULT 2004,
  ADD COLUMN IF NOT EXISTS category_uid integer NOT NULL DEFAULT 2,
  ADD COLUMN IF NOT EXISTS type_uid bigint,
  ADD COLUMN IF NOT EXISTS activity_id integer NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS severity_id integer,
  ADD COLUMN IF NOT EXISTS status_id integer,
  ADD COLUMN IF NOT EXISTS status_code text,
  ADD COLUMN IF NOT EXISTS status_detail text,
  ADD COLUMN IF NOT EXISTS "time" timestamptz,
  ADD COLUMN IF NOT EXISTS finding_info jsonb,
  ADD COLUMN IF NOT EXISTS metadata jsonb,
  ADD COLUMN IF NOT EXISTS cloud jsonb,
  ADD COLUMN IF NOT EXISTS vulnerabilities jsonb,
  ADD COLUMN IF NOT EXISTS observables jsonb,
  ADD COLUMN IF NOT EXISTS unmapped jsonb,
  ADD COLUMN IF NOT EXISTS evidences jsonb,
  ADD COLUMN IF NOT EXISTS evidences_truncated boolean NOT NULL DEFAULT false;

-- Dynamic, because on a blank database the old columns were never created and a
-- static reference to them would fail to parse.
DO $$
DECLARE
  has_old boolean;
BEGIN
  IF to_regclass('findings') IS NULL THEN
    RETURN;
  END IF;
  SELECT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'findings' AND column_name = 'template_id'
  ) INTO has_old;
  IF NOT has_old THEN
    RETURN;
  END IF;

  -- Identity first: check_id and engine are what the lifecycle, the catalogue
  -- and every stored mute rule key on, and they simply move.
  EXECUTE $sql$
    UPDATE findings SET
      check_id = template_id,
      engine   = type
    WHERE check_id IS NULL
  $sql$;

  -- matcher_name is the column this whole redesign exists to delete: four
  -- engines wrote four incompatible meanings into it. Only prowler's is carried
  -- across generically, because only prowler's was already an OCSF value — its
  -- status_code — and it moves to the column of that name. The other three get
  -- real homes of their own rather than a shared one (024 composes nuclei's
  -- matcher into check_id and collapses inspec's assertions; trivy's record
  -- class is a finding_info type), so translating them here would recreate the
  -- conflation on the way out.
  --
  -- 021 reads status_code afterwards to recover the manual verdicts. It runs in
  -- the post phase, by which point matcher_name is gone, so this is the only
  -- moment the value can be moved.
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'findings' AND column_name = 'matcher_name'
  ) THEN
    EXECUTE $sql$
      UPDATE findings SET status_code = matcher_name
      WHERE status_code IS NULL
        AND type = 'prowler'
        AND COALESCE(matcher_name, '') <> ''
    $sql$;
  END IF;

  -- Recon's severity ladder onto OCSF's scale. They are the same ladder; only
  -- the bottom rung is renamed, and anything unrecognised becomes 0 (Unknown)
  -- rather than being guessed at.
  EXECUTE $sql$
    UPDATE findings SET severity_id = CASE lower(coalesce(severity, ''))
      WHEN 'critical' THEN 5
      WHEN 'high'     THEN 4
      WHEN 'medium'   THEN 3
      WHEN 'low'      THEN 2
      WHEN 'info'     THEN 1
      ELSE 0
    END
    WHERE severity_id IS NULL
  $sql$;

  -- finding_info is OCSF's "what was found". The description used to be
  -- reachable only as raw.info.description, which is where the browser dug for
  -- it on every engine; tags become finding_info.types, which is the nearest
  -- thing OCSF has to recon's labels.
  EXECUTE $sql$
    UPDATE findings SET finding_info = jsonb_strip_nulls(jsonb_build_object(
      'uid',   template_id,
      'title', name,
      'desc',  NULLIF(coalesce(raw -> 'info' ->> 'description', raw ->> 'risk_details', ''), ''),
      'types', CASE WHEN coalesce(array_length(tags, 1), 0) > 0
                    THEN to_jsonb(tags) ELSE NULL END,
      'src_url', NULLIF(coalesce(raw -> 'info' ->> 'reference', ''), '')
    ))
    WHERE finding_info IS NULL
  $sql$;

  EXECUTE $sql$
    UPDATE findings SET metadata = jsonb_strip_nulls(jsonb_build_object(
      'version',    '1.5.0',
      'event_code', template_id,
      'product',    jsonb_build_object('name', type, 'vendor_name', 'flanksource-recon'),
      'profiles',   CASE WHEN type = 'prowler'
                         THEN jsonb_build_array('cloud') ELSE NULL END
    ))
    WHERE metadata IS NULL
  $sql$;

  -- remediation was two flat columns; OCSF models it as one object.
  EXECUTE $sql$
    UPDATE findings SET remediation = jsonb_strip_nulls(jsonb_build_object(
      'desc',       NULLIF(coalesce(remediation_text, ''), ''),
      'references', CASE WHEN coalesce(array_length(reference, 1), 0) > 0
                         THEN to_jsonb(reference) ELSE NULL END
    ))
    WHERE remediation IS NULL
      AND (coalesce(remediation_text, '') <> '' OR coalesce(array_length(reference, 1), 0) > 0)
  $sql$;

  -- Prowler recorded the account at the event level, which is exactly where
  -- OCSF wants it.
  EXECUTE $sql$
    UPDATE findings SET cloud = jsonb_strip_nulls(jsonb_build_object(
      'provider', NULLIF(coalesce(
        raw -> 'cloud' ->> 'provider', raw -> 'unmapped' ->> 'provider', ''), ''),
      'account',  CASE WHEN coalesce(raw -> 'cloud' -> 'account' ->> 'uid',
                                     raw -> 'unmapped' ->> 'provider_uid', '') <> ''
                       THEN jsonb_strip_nulls(jsonb_build_object(
                              'uid',  NULLIF(coalesce(raw -> 'cloud' -> 'account' ->> 'uid',
                                                      raw -> 'unmapped' ->> 'provider_uid', ''), ''),
                              'name', NULLIF(coalesce(raw -> 'cloud' -> 'account' ->> 'name', ''), '')))
                       ELSE NULL END,
      'region',   NULLIF(coalesce(raw -> 'cloud' ->> 'region', ''), '')
    ))
    WHERE cloud IS NULL AND raw IS NOT NULL
      AND coalesce(raw -> 'cloud' ->> 'provider', raw -> 'unmapped' ->> 'provider', '') <> ''
  $sql$;

  -- The HTTP exchange nuclei recorded, in the place OCSF defines for it. An
  -- entry has to carry one of the attributes the evidences constraint names, so
  -- a finding with neither request nor response gets no entry rather than an
  -- empty one.
  EXECUTE $sql$
    UPDATE findings SET evidences = jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
      'http_request',  CASE WHEN coalesce(request, '') <> ''
                            THEN jsonb_build_object('args', request) ELSE NULL END,
      'http_response', CASE WHEN coalesce(response, '') <> ''
                            THEN jsonb_build_object('message', response) ELSE NULL END,
      'url',           CASE WHEN coalesce(matched_at, '') <> ''
                            THEN jsonb_build_object('url_string', matched_at) ELSE NULL END,
      'data',          CASE WHEN coalesce(curl, '') <> '' OR coalesce(array_length(extracted, 1), 0) > 0
                            THEN jsonb_strip_nulls(jsonb_build_object(
                                   'curl',      NULLIF(coalesce(curl, ''), ''),
                                   'extracted', CASE WHEN coalesce(array_length(extracted, 1), 0) > 0
                                                     THEN to_jsonb(extracted) ELSE NULL END))
                            ELSE NULL END
    )))
    WHERE evidences IS NULL
      AND (coalesce(request, '') <> '' OR coalesce(response, '') <> ''
           OR coalesce(curl, '') <> '' OR coalesce(array_length(extracted, 1), 0) > 0)
  $sql$;

  -- Whatever of the engine's record has no modelled home, in OCSF's own escape
  -- hatch rather than a recon-specific column.
  EXECUTE $sql$
    UPDATE findings SET unmapped = raw - 'resources' - 'cloud' - 'info' - 'unmapped'
    WHERE unmapped IS NULL AND raw IS NOT NULL
  $sql$;

  -- Quoted on both sides: `timestamp` is a type name as well as the old column's
  -- name, and unquoted it parses as the former.
  EXECUTE $sql$ UPDATE findings SET "time" = "timestamp" WHERE "time" IS NULL $sql$;
END $$;

-- Required by OCSF on every event, so no row may leave this migration without
-- them — including a row whose old columns held nothing to derive them from.
--
-- Dynamic like the block above: in the pre phase of a blank database the diff
-- has not created findings yet, and a static reference would fail to parse
-- rather than finding no rows to fix.
DO $$
BEGIN
  IF to_regclass('findings') IS NULL THEN
    RETURN;
  END IF;
  EXECUTE $sql$
    UPDATE findings SET
      severity_id = COALESCE(severity_id, 0),
      check_id    = COALESCE(check_id, ''),
      type_uid    = COALESCE(type_uid, class_uid::bigint * 100 + activity_id)
    WHERE severity_id IS NULL OR check_id IS NULL OR type_uid IS NULL
  $sql$;
  EXECUTE $sql$
    UPDATE findings
    SET finding_info = jsonb_build_object('uid', check_id, 'title', check_id)
    WHERE finding_info IS NULL
  $sql$;
  EXECUTE $sql$
    UPDATE findings
    SET metadata = jsonb_build_object('version', '1.5.0', 'event_code', check_id)
    WHERE metadata IS NULL
  $sql$;
END $$;
