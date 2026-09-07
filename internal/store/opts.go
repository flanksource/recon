package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// scopeTargets applies database predicates; label matching runs after rows load.
func scopeTargets(db *gorm.DB, o api.TargetSelector) (*gorm.DB, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if len(o.IDs) > 0 {
		db = db.Where("id = ANY(?)", pq.StringArray(o.IDs))
	}
	if len(o.Kind) > 0 {
		db = db.Where("kind = ANY(?)", pq.StringArray(o.Kind))
	}
	if len(o.Provider) > 0 {
		db = db.Where("provider = ANY(?)", pq.StringArray(o.Provider))
	}
	if len(o.Class) > 0 {
		db = db.Where("class = ANY(?)", pq.StringArray(o.Class))
	}
	if len(o.Tags) > 0 {
		db = tagPredicate(db, "tags", o.Tags)
	}
	if len(o.Profiles) > 0 {
		db = db.Where("profiles && ?", pq.StringArray(o.Profiles))
	}
	if len(o.Hosts) > 0 {
		db = db.Where("host = ANY(?)", pq.StringArray(o.Hosts))
	}
	// Match curated ports and discovery results, not just one source.
	if len(o.Ports) > 0 {
		clauses := []string{"ports && ?", "(http ->> 'port')::int = ANY(?)"}
		args := []any{pq.Int64Array(int64s(o.Ports)), pq.Int64Array(int64s(o.Ports))}
		for _, port := range o.Ports {
			clauses = append(clauses, "network -> 'open_ports' @> ?::jsonb")
			args = append(args, strconv.Itoa(port))
		}
		db = db.Where("("+strings.Join(clauses, " OR ")+")", args...)
	}
	// These expressions must match the expression indexes for Postgres to use them.
	if len(o.Status) > 0 {
		db = db.Where("(http ->> 'status_code')::int = ANY(?)", pq.Int64Array(int64s(o.Status)))
	}
	if o.LastSeen != "" {
		since, err := api.ParseSince(o.LastSeen)
		if err != nil {
			return nil, err
		}
		db = db.Where("(observed ->> 'last_seen') >= ?", since.Format(time.RFC3339))
	}
	if o.Live {
		// Failed probes preserve the last good status code, so check both fields.
		db = db.Where("(http ->> 'status_code') IS NOT NULL").
			Where("COALESCE(http ->> 'failed', 'false') <> 'true'")
	}
	if len(o.Failure) > 0 {
		db = db.Where("(observed ->> 'failure') = ANY(?)", pq.StringArray(o.Failure))
	}
	return db, nil
}

// stringArray is the pq wrapper every ANY(?) predicate needs.
func stringArray(values []string) pq.StringArray { return pq.StringArray(values) }

// tagPredicate applies ! exclusions to the whole array, not individual elements.
// Only exclusions means everything not excluded; wildcards are not supported.
func tagPredicate(db *gorm.DB, column string, patterns []string) *gorm.DB {
	include, exclude := partitionTags(patterns)
	if len(include) > 0 {
		db = db.Where(column+" && ?", stringArray(include))
	}
	if len(exclude) > 0 {
		db = db.Where("NOT ("+column+" && ?)", stringArray(exclude))
	}
	return db
}

// scalarPredicate uses the same exclusion grammar with scalar SQL operators.
func scalarPredicate(db *gorm.DB, column string, patterns []string) *gorm.DB {
	include, exclude := partitionTags(patterns)
	if len(include) > 0 {
		db = db.Where(column+" = ANY(?)", stringArray(include))
	}
	if len(exclude) > 0 {
		db = db.Where("NOT ("+column+" = ANY(?))", stringArray(exclude))
	}
	return db
}

func labelPredicate(db *gorm.DB, column string, patterns []string) (*gorm.DB, error) {
	include, exclude := partitionTags(patterns)
	build := func(values []string) (string, []any, error) {
		parts := make([]string, 0, len(values))
		args := make([]any, 0, len(values))
		for _, value := range values {
			key, label, found := strings.Cut(value, ":")
			if !found || key == "" {
				return "", nil, fmt.Errorf("invalid label %q: expected key:value", value)
			}
			encoded, err := json.Marshal(map[string]string{key: label})
			if err != nil {
				return "", nil, fmt.Errorf("encode label %q: %w", value, err)
			}
			parts = append(parts, column+" @> CAST(? AS jsonb)")
			args = append(args, string(encoded))
		}
		return strings.Join(parts, " OR "), args, nil
	}
	if clause, args, err := build(include); err != nil {
		return nil, err
	} else if clause != "" {
		db = db.Where("("+clause+")", args...)
	}
	if clause, args, err := build(exclude); err != nil {
		return nil, err
	} else if clause != "" {
		db = db.Where("NOT ("+clause+")", args...)
	}
	return db, nil
}

func partitionTags(patterns []string) (include, exclude []string) {
	for _, pattern := range patterns {
		if after, found := strings.CutPrefix(pattern, "!"); found {
			exclude = append(exclude, after)
			continue
		}
		include = append(include, pattern)
	}
	return include, exclude
}

func int64s(values []int) []int64 {
	out := make([]int64, len(values))
	for i, value := range values {
		out[i] = int64(value)
	}
	return out
}
