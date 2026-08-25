package store

import (
	"fmt"

	"gorm.io/gorm"
)

// The check catalogue: what a check is, kept where a resolved finding can still
// reach it.
//
// CAST(@x AS type) throughout and never a named parameter inside a comment —
// see the header of finding_states.go, and checks_sql_test.go, which is what
// stops either rule being broken silently.

// upsertChecksSQL records every check the run described.
//
// DISTINCT ON for the reason openFromFindingsSQL needs it: a run reports one
// check many times, and two rows reaching one ON CONFLICT target makes Postgres
// raise "ON CONFLICT DO UPDATE command cannot affect row a second time" and
// abort the whole finalize transaction.
//
// Deliberately not filtered to findings that name a resource. The catalogue
// describes checks, and a check is worth naming whether or not this engine
// resolved its subject to a row recon holds.
const upsertChecksSQL = `
INSERT INTO checks (
    engine, check_id, name, severity, type, remediation, reference, tags,
    first_seen, last_seen, created_at, updated_at
)
SELECT CAST(@engine AS text), f.check_id,
       COALESCE(f.finding_info ->> 'title', f.check_id),
       ` + severityText + `,
       f.engine, f.remediation ->> 'desc',
       COALESCE(ARRAY(SELECT jsonb_array_elements_text(f.remediation -> 'references')), '{}'),
       f.tags,
       CAST(@at AS timestamptz), CAST(@at AS timestamptz), now(), now()
FROM (
    -- Only the identity and description columns, not the whole row: the record
    -- also carries the evidence, and sorting the lot to pick one row per check
    -- dragged every engine's payload through the sort.
    SELECT DISTINCT ON (check_id)
           check_id, engine, severity_id, finding_info, remediation, tags, line_no
    FROM findings
    WHERE scan_id = CAST(@scan AS uuid) AND check_id <> ''
    ORDER BY check_id, line_no
) f
ON CONFLICT (engine, check_id) DO UPDATE SET
    -- A run that reported no description must not blank one an earlier run
    -- supplied: the same rule upsertResources applies to a resource's
    -- descriptive fields, and for the same reason.
    name        = COALESCE(NULLIF(EXCLUDED.name, ''), checks.name),
    severity    = COALESCE(NULLIF(EXCLUDED.severity, 'unknown'), checks.severity),
    type        = COALESCE(EXCLUDED.type, checks.type),
    remediation = COALESCE(EXCLUDED.remediation, checks.remediation),
    reference   = CASE WHEN cardinality(EXCLUDED.reference) > 0
                       THEN EXCLUDED.reference ELSE checks.reference END,
    tags        = CASE WHEN cardinality(EXCLUDED.tags) > 0
                       THEN EXCLUDED.tags ELSE checks.tags END,
    first_seen  = LEAST(checks.first_seen, EXCLUDED.first_seen),
    last_seen   = GREATEST(checks.last_seen, EXCLUDED.last_seen),
    updated_at  = now()
-- Never regress on a replayed or out-of-order run, the guard every other
-- statement in this subsystem now carries.
WHERE EXCLUDED.last_seen >= checks.last_seen`

// catalogueSQL reads the entries a page of states needs.
//
// Joined through unnest rather than filtered by `check_id = ANY(...)`, because
// the key is the pair: two engines can own the same check id, and matching on
// the id alone would render one engine's check with the other's description.
const catalogueSQL = `
SELECT checks.*
FROM checks
JOIN unnest(CAST(@engines AS text[]), CAST(@checks AS text[])) AS want(engine, check_id)
  ON want.engine = checks.engine AND want.check_id = checks.check_id`

// upsertChecks folds the run's check descriptions into the catalogue.
func upsertChecks(db *gorm.DB, scanID, engine string, at any) error {
	if err := db.Exec(upsertChecksSQL, map[string]any{
		"scan": scanID, "engine": engine, "at": at,
	}).Error; err != nil {
		return fmt.Errorf("record checks for %s: %w", scanID, err)
	}
	return nil
}
