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
  -- and every stored mute rule key on.
  --
  -- check_id simply moves. `engine` cannot come from the column named `type`,
  -- because that column is the conflation this redesign exists to delete: for
  -- prowler and trivy it held the engine, for nuclei it held the protocol a
  -- template spoke — so copying it across labels every nuclei finding "dns" or
  -- "http", or nothing at all when the host never answered. The run knows which
  -- scanner produced its findings, for all four engines, so it is the source.
  --
  -- The protocol is not lost: it moves to unmapped.protocol below, which is the
  -- key the nuclei adapter writes it under.
  EXECUTE $sql$
    UPDATE findings f SET
      check_id = f.template_id,
      engine   = COALESCE(NULLIF(s.engine, ''), NULLIF(f.type, ''))
    FROM scans s
    WHERE s.id = f.scan_id AND f.check_id IS NULL
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

  -- What the finding means, which is the half of it triage reads and which had
  -- no home before: `impact` is nuclei's word and `risk_details` prowler's, and
  -- the browser dug for both under raw.info on every engine.
  EXECUTE $sql$
    UPDATE findings SET
      impact       = NULLIF(coalesce(raw -> 'info' ->> 'impact', ''), ''),
      risk_details = NULLIF(coalesce(raw ->> 'risk_details', ''), '')
    WHERE impact IS NULL AND risk_details IS NULL AND raw IS NOT NULL
  $sql$;

  -- finding_info is OCSF's "what was found". The description used to be
  -- reachable only by digging, and under a different key per engine — prowler
  -- emits OCSF and spells it finding_info.desc, nuclei spells it
  -- info.description; tags become finding_info.types, which is the nearest
  -- thing OCSF has to recon's labels.
  EXECUTE $sql$
    UPDATE findings SET finding_info = jsonb_strip_nulls(jsonb_build_object(
      'uid',   template_id,
      'title', name,
      'desc',  NULLIF(coalesce(
                 raw -> 'finding_info' ->> 'desc',
                 raw -> 'info' ->> 'description', ''), ''),
      'types', CASE WHEN coalesce(array_length(tags, 1), 0) > 0
                    THEN to_jsonb(tags) ELSE NULL END,
      -- One URL, not the list: nuclei writes info.reference as an array, and
      -- ->> on an array renders the whole JSON text into a field the schema
      -- types as a single link.
      'src_url', NULLIF(coalesce(
        CASE jsonb_typeof(raw -> 'info' -> 'reference')
          WHEN 'array'  THEN raw -> 'info' -> 'reference' ->> 0
          WHEN 'string' THEN raw -> 'info' ->> 'reference'
        END, ''), '')
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
      -- Which host actually answered, which a URL does not say. The adapter
      -- writes it here too, from the same two fields of nuclei's record.
      'dst_endpoint',  CASE WHEN coalesce(raw ->> 'ip', '') <> ''
                            THEN jsonb_strip_nulls(jsonb_build_object(
                                   'ip',       raw ->> 'ip',
                                   'hostname', NULLIF(coalesce(raw ->> 'host', ''), ''),
                                   'port',     CASE WHEN raw ->> 'port' ~ '^[0-9]+$'
                                                    THEN (raw ->> 'port')::int END))
                            ELSE NULL END,
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
  --
  -- Named keys rather than "the record minus what was recognised". Copying the
  -- rest wholesale would move the verbatim payload from `raw` to `unmapped` and
  -- change nothing: the same unbounded blob, every attribute stored twice
  -- beside the column that now holds it, and — for trivy — the masked secret
  -- its adapter deliberately refuses to carry. What the rest of the record said
  -- is still in the run's retained artifact, which is where it belongs.
  --
  -- Each engine's list is its adapter's, so a migrated row and one ingested
  -- today carry the same keys spelled the same way. nuclei's raw record calls
  -- the protocol `type` — the word the old column used for the engine — and its
  -- matcher `matcher-name`; both are renamed to what the adapter writes, since
  -- one fact spelled two ways is one no expression can read. trivy and inspec
  -- populate nothing, and so does this.
  EXECUTE $sql$
    UPDATE findings SET unmapped = NULLIF(
      CASE engine
        WHEN 'prowler' THEN
          -- prowler's own escape hatch. The compliance mappings are the reason
          -- this is not dropped: its checks are organised by framework, and
          -- "which CIS control does this fail" is the audit's actual question.
          jsonb_strip_nulls(jsonb_build_object(
            'categories', raw -> 'unmapped' -> 'categories',
            'compliance', raw -> 'unmapped' -> 'compliance'))
        WHEN 'nuclei' THEN
          CASE WHEN COALESCE(raw ->> 'type', '') <> ''
               THEN jsonb_build_object('protocol', raw ->> 'type') ELSE '{}'::jsonb END ||
          CASE WHEN COALESCE(raw ->> 'matcher-name', '') <> ''
               THEN jsonb_build_object('matcher_name', raw ->> 'matcher-name') ELSE '{}'::jsonb END ||
          CASE WHEN jsonb_typeof(raw -> 'info' -> 'author') = 'array'
               THEN jsonb_build_object('authors', raw -> 'info' -> 'author') ELSE '{}'::jsonb END
        ELSE '{}'::jsonb
      END, '{}'::jsonb)
    WHERE unmapped IS NULL AND raw IS NOT NULL
  $sql$;

  -- Quoted on both sides: `timestamp` is a type name as well as the old column's
  -- name, and unquoted it parses as the former.
  --
  -- The record is read when the column has nothing, which is prowler's whole
  -- population: it spells time_dt without a zone, the old ingest parsed it as
  -- RFC3339, that refuses a zoneless stamp, and the column was left NULL for
  -- every prowler finding ever stored. `time` is prowler's epoch field, which is
  -- seconds however much OCSF says milliseconds — see recordTime.
  EXECUTE $sql$
    UPDATE findings SET "time" = COALESCE(
      "timestamp",
      CASE WHEN raw ->> 'time_dt' ~ '^\d{4}-' THEN (raw ->> 'time_dt')::timestamptz END,
      CASE WHEN raw ->> 'time' ~ '^\d+$' THEN to_timestamp((raw ->> 'time')::bigint) END)
    WHERE "time" IS NULL
  $sql$;
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
