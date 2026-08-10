package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/flanksource/recon/internal/api"
)

// TargetOpts selects targets. It is the one selector in the system: the same
// struct is the CLI's flags, the REST query string, the UI's filter bar and —
// once resolved to endpoints — what a scan runs against. A scan records the
// TargetOpts it ran with, so "what did this actually hit" has an answer.
//
// Every list-valued field means "any of", matching how the filter chips read.
type TargetOpts struct {
	Selector string   `json:"selector,omitempty" flag:"selector" help:"Kubernetes label selector over target tags"`
	Class    []string `json:"class,omitempty" flag:"class" help:"Only these classes (public, prod, non-prod, internal, unclassified, deactivated)"`
	Tags     []string `json:"tags,omitempty" flag:"tags" help:"Only targets carrying any of these tags"`
	Profiles []string `json:"profiles,omitempty" flag:"profiles" help:"Only targets assigned any of these scan profiles"`
	Hosts    []string `json:"hosts,omitempty" flag:"hosts" help:"Only these exact hosts"`
	Ports    []int    `json:"ports,omitempty" flag:"ports" help:"Only targets with any of these ports, curated or discovered"`
	Status   []int    `json:"status,omitempty" flag:"status" help:"Only targets whose last HTTP status was one of these"`

	LastSeen string `json:"lastSeen,omitempty" flag:"last-seen" help:"Only targets seen since this time (RFC3339 or a duration such as 168h)"`
	Live     bool   `json:"live,omitempty" flag:"live" help:"Only targets that answered over HTTP the last time they were probed"`
}

// Empty reports whether the selector constrains anything. A scan against an
// empty selector targets the whole inventory, which is worth saying out loud
// before it runs.
func (o TargetOpts) Empty() bool {
	return o.Selector == "" && len(o.Class) == 0 && len(o.Tags) == 0 && len(o.Profiles) == 0 &&
		len(o.Hosts) == 0 && len(o.Ports) == 0 && len(o.Status) == 0 &&
		o.LastSeen == "" && !o.Live
}

// Describe renders the selector as the phrase used in confirmation prompts and
// stored on the scan row.
func (o TargetOpts) Describe() string {
	if o.Empty() {
		return "every target"
	}
	var parts []string
	add := func(label string, values []string) {
		if len(values) > 0 {
			parts = append(parts, label+" "+strings.Join(values, ","))
		}
	}
	add("class", o.Class)
	if o.Selector != "" {
		parts = append(parts, "selector "+o.Selector)
	}
	add("tags", o.Tags)
	add("profiles", o.Profiles)
	add("hosts", o.Hosts)
	if len(o.Ports) > 0 {
		parts = append(parts, fmt.Sprintf("ports %v", o.Ports))
	}
	if len(o.Status) > 0 {
		parts = append(parts, fmt.Sprintf("status %v", o.Status))
	}
	if o.LastSeen != "" {
		parts = append(parts, "seen since "+o.LastSeen)
	}
	if o.Live {
		parts = append(parts, "live")
	}
	return strings.Join(parts, ", ")
}

// Validate rejects a selector that cannot mean anything, rather than silently
// returning nothing and letting the caller conclude the inventory is empty.
func (o TargetOpts) Validate() error {
	if _, err := labels.Parse(o.Selector); err != nil {
		return fmt.Errorf("invalid selector %q: %w", o.Selector, err)
	}
	valid := map[string]bool{}
	for _, class := range api.Classes() {
		valid[string(class)] = true
	}
	for _, class := range o.Class {
		if !valid[class] {
			return fmt.Errorf("unknown class %q: expected one of %s",
				class, strings.Join(classNames(), ", "))
		}
	}
	for _, port := range o.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("port %d out of range", port)
		}
	}
	if o.LastSeen != "" {
		if _, err := parseSince(o.LastSeen); err != nil {
			return err
		}
	}
	return nil
}

func classNames() []string {
	names := make([]string, 0, len(api.Classes()))
	for _, class := range api.Classes() {
		names = append(names, string(class))
	}
	return names
}

// parseSince accepts either an absolute RFC3339 timestamp or a duration back
// from now, because "--last-seen 168h" is what anyone actually wants to type.
func parseSince(value string) (time.Time, error) {
	if duration, err := time.ParseDuration(value); err == nil {
		if duration > 0 {
			duration = -duration
		}
		return time.Now().Add(duration), nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf(
			"last-seen %q is neither a duration (168h) nor an RFC3339 time", value)
	}
	return parsed, nil
}

// Scope pushes the indexed target fields into SQL. The Kubernetes tag selector
// is evaluated against the packed text[] tag representation after rows are
// loaded; every other predicate here has an index behind it.
func (o TargetOpts) Scope(db *gorm.DB) (*gorm.DB, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	if len(o.Class) > 0 {
		db = db.Where("class = ANY(?)", pq.StringArray(o.Class))
	}
	// && is array overlap: any of these, matching how the filter chips read.
	if len(o.Tags) > 0 {
		db = db.Where("tags && ?", pq.StringArray(o.Tags))
	}
	if len(o.Profiles) > 0 {
		db = db.Where("profiles && ?", pq.StringArray(o.Profiles))
	}
	if len(o.Hosts) > 0 {
		db = db.Where("host = ANY(?)", pq.StringArray(o.Hosts))
	}
	// A port is worth selecting on wherever it is known: curated by hand,
	// discovered by naabu, or the one that answered over HTTP. Matching only the
	// curated column would drop exactly the hosts discovery just found, which is
	// the opposite of useful.
	if len(o.Ports) > 0 {
		clauses := []string{"ports && ?", "(http ->> 'port')::int = ANY(?)"}
		args := []any{pq.Int64Array(int64s(o.Ports)), pq.Int64Array(int64s(o.Ports))}
		for _, port := range o.Ports {
			clauses = append(clauses, "network -> 'open_ports' @> ?::jsonb")
			args = append(args, strconv.Itoa(port))
		}
		db = db.Where("("+strings.Join(clauses, " OR ")+")", args...)
	}
	// The predicates below must be written exactly as the expression indexes
	// declare them, or Postgres will not use them.
	if len(o.Status) > 0 {
		db = db.Where("(http ->> 'status_code')::int = ANY(?)", pq.Int64Array(int64s(o.Status)))
	}
	if o.LastSeen != "" {
		since, err := parseSince(o.LastSeen)
		if err != nil {
			return nil, err
		}
		db = db.Where("(observed ->> 'last_seen') >= ?", since.Format(time.RFC3339))
	}
	if o.Live {
		// A target that answered has a status code; one whose last probe failed
		// carries observed.error and no http section at all.
		db = db.Where("(http ->> 'status_code') IS NOT NULL")
	}
	return db, nil
}

// MatchesTags applies Selector to one target's tag set. Bare tags become label
// keys with an empty value; key=value tags become ordinary Kubernetes labels.
func (o TargetOpts) MatchesTags(tags []string) (bool, error) {
	selector, err := labels.Parse(o.Selector)
	if err != nil {
		return false, fmt.Errorf("invalid selector %q: %w", o.Selector, err)
	}
	if o.Selector == "" {
		return true, nil
	}
	set := labels.Set{}
	for _, tag := range tags {
		key, value, found := strings.Cut(tag, "=")
		if !found {
			key, value = tag, ""
		}
		if key == "" {
			return false, fmt.Errorf("invalid empty tag key in %q", tag)
		}
		if existing, exists := set[key]; exists && existing != value {
			return false, fmt.Errorf("conflicting values for tag %q", key)
		}
		set[key] = value
	}
	return selector.Matches(set), nil
}

// stringArray is the pq wrapper every ANY(?) predicate needs.
func stringArray(values []string) pq.StringArray { return pq.StringArray(values) }

// Map renders the selector for storage on a scan row. Going through JSON rather
// than reflection keeps it identical to what the API accepts, so a stored
// selector can be replayed.
func (o TargetOpts) Map() (map[string]any, error) {
	encoded, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("encode target selector: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, fmt.Errorf("project target selector: %w", err)
	}
	return out, nil
}

// TargetOptsFrom rebuilds a selector from what was stored on a scan row.
func TargetOptsFrom(stored map[string]any) (TargetOpts, error) {
	encoded, err := json.Marshal(stored)
	if err != nil {
		return TargetOpts{}, fmt.Errorf("encode stored target selector: %w", err)
	}
	var opts TargetOpts
	if err := json.Unmarshal(encoded, &opts); err != nil {
		return TargetOpts{}, fmt.Errorf("decode stored target selector: %w", err)
	}
	if err := opts.Validate(); err != nil {
		return TargetOpts{}, fmt.Errorf("validate stored target selector: %w", err)
	}
	return opts, nil
}

func int64s(values []int) []int64 {
	out := make([]int64, len(values))
	for i, value := range values {
		out[i] = int64(value)
	}
	return out
}
