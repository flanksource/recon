package store

import (
	"context"
	"fmt"
)

// Vocabulary names a set of distinct values a field is actually filtered by.
//
// A filter with no options is a text box, and a text box over tags, hosts or
// template ids is only usable by someone who already knows what the sweep
// found. These are the queries behind the option sets, kept together so the
// shell completions and the web filter bar cannot come to disagree about what
// exists.
type Vocabulary string

const (
	TargetTags      Vocabulary = "target.tags"
	TargetProfiles  Vocabulary = "target.profiles"
	TargetIDs       Vocabulary = "target.ids"
	TargetHosts     Vocabulary = "target.hosts"
	TargetProviders Vocabulary = "target.providers"
	TargetPorts     Vocabulary = "target.ports"
	TargetStatus    Vocabulary = "target.status"

	ScanNames    Vocabulary = "scan.name"
	ScanProfiles Vocabulary = "scan.profile"

	FindingHosts     Vocabulary = "finding.host"
	FindingTargets   Vocabulary = "finding.target"
	FindingTemplates Vocabulary = "finding.template"
	FindingTags      Vocabulary = "finding.tag"

	ProbeHosts Vocabulary = "probe.host"

	ProfileNames Vocabulary = "profile.name"
)

// vocabularies is the SQL behind each option set.
//
// Every query returns one text column named value. Order is not cosmetic: an
// option set larger than the lookup cap is served head-first, so the ordering
// decides which values a user can pick without typing. The numeric ones
// therefore sort on the number rather than on its text, or 8443 would come
// before 80 and the common ports would fall outside the head.
var vocabularies = map[Vocabulary]string{
	TargetTags:     `SELECT DISTINCT unnest(tags) AS value FROM targets ORDER BY value`,
	TargetProfiles: `SELECT DISTINCT unnest(profiles) AS value FROM targets ORDER BY value`,
	TargetIDs:      `SELECT id AS value FROM targets ORDER BY id COLLATE "C"`,
	// COLLATE "C" for the same reason the listing uses it: byte order is the
	// order the hosts were captured in, and it must not drift with the
	// database's default collation.
	TargetHosts:     `SELECT host AS value FROM targets WHERE host IS NOT NULL ORDER BY host COLLATE "C"`,
	TargetProviders: `SELECT DISTINCT provider AS value FROM targets WHERE provider IS NOT NULL ORDER BY provider`,

	// A port is offerable wherever it is known — curated by hand, found by
	// naabu, or the one that answered over HTTP — matching what the selector
	// matches on. Offering only the curated column would omit exactly the ports
	// discovery just found.
	TargetPorts: `
		SELECT DISTINCT ON (port) port::text AS value
		FROM (
			SELECT unnest(ports) AS port FROM targets
			UNION ALL
			SELECT (http ->> 'port')::int FROM targets
			UNION ALL
			SELECT (jsonb_array_elements_text(network -> 'open_ports'))::int FROM targets
		) ports
		WHERE port IS NOT NULL
		ORDER BY port`,

	// Written as the expression index declares it, or Postgres will not use it.
	TargetStatus: `
		SELECT DISTINCT ON (code) code::text AS value
		FROM (SELECT (http ->> 'status_code')::int AS code FROM targets) statuses
		WHERE code IS NOT NULL
		ORDER BY code`,

	// Newest first: a run is picked from the recent ones, not alphabetically.
	ScanNames:    `SELECT name AS value FROM scans ORDER BY started_at DESC NULLS LAST`,
	ScanProfiles: `SELECT DISTINCT profile AS value FROM scans ORDER BY profile`,

	// The collation is inside the select list because DISTINCT requires every
	// ORDER BY expression to be there.
	FindingHosts:     `SELECT DISTINCT host COLLATE "C" AS value FROM findings ORDER BY value`,
	FindingTargets:   `SELECT DISTINCT target_id COLLATE "C" AS value FROM findings WHERE target_id IS NOT NULL ORDER BY value`,
	FindingTemplates: `SELECT DISTINCT template_id AS value FROM findings ORDER BY template_id`,
	FindingTags:      `SELECT DISTINCT unnest(tags) AS value FROM findings ORDER BY value`,

	// Every host any sweep has probed, not just the ones in the inventory now: a
	// probe's history outlives the target it was taken of, and filtering it by a
	// vocabulary that had already forgotten the host would hide exactly the runs
	// that explain why it went away.
	ProbeHosts: `SELECT DISTINCT host COLLATE "C" AS value FROM probe_results ORDER BY value`,

	ProfileNames: `SELECT DISTINCT name AS value FROM engine_profiles ORDER BY name`,
}

// Vocabulary returns every distinct value of a filterable field.
//
// An unknown vocabulary is a wiring mistake and says so, rather than returning
// nothing and letting a filter render as permanently empty.
func (s *Store) Vocabulary(ctx context.Context, of Vocabulary) ([]string, error) {
	query, known := vocabularies[of]
	if !known {
		return nil, fmt.Errorf("no vocabulary query for %q", of)
	}

	var values []string
	if err := s.DB(ctx).Raw(query).Scan(&values).Error; err != nil {
		return nil, fmt.Errorf("%s vocabulary: %w", of, err)
	}
	if values == nil {
		values = []string{}
	}
	return values, nil
}

// Vocabularies lists every declared vocabulary, so a test can assert that each
// one is a query this database will actually run.
func Vocabularies() []Vocabulary {
	all := make([]Vocabulary, 0, len(vocabularies))
	for name := range vocabularies {
		all = append(all, name)
	}
	return all
}
