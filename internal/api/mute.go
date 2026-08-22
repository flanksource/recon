package api

import (
	"fmt"
	"regexp"
	"strings"
)

// muteNamePattern mirrors engine_profiles_name_format, so a rule name is always
// safe to use as a filename fragment and as a key in a run's mutes.json.
var muteNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// MuteRule suppresses findings someone has decided not to act on.
//
// A rule has two effects. Where the engine can express the same exclusion
// natively the check is never run, which is the only form of muting that saves
// any time. Everything else is applied to the results: a matching finding is
// dropped before the run is recorded, and the run's mutes.json says which rule
// removed which line of the engine's own output.
//
// The dimensions are ANDed and the values within one are ORed — the semantics
// TargetOpts already documents. An empty dimension is unconstrained rather than
// unsatisfiable; a rule that constrains nothing at all is refused rather than
// stored, because the failure mode of an accidentally universal mute is a clean
// scan that is not clean.
type MuteRule struct {
	Name string `json:"name"`

	// Comment is optional. Nothing here is required beyond a name and something
	// to select on: a rule nobody can create is a rule nobody uses.
	Comment string `json:"comment,omitempty"`

	// Disabled suspends a rule without deleting it. There is no expiry, so this
	// is the only way to turn one off and keep it.
	Disabled bool `json:"disabled,omitempty"`

	// Engines narrows which engines the rule applies to. It is a precondition,
	// not a selector: it says which runs the rule is considered for, and on its
	// own it selects no finding. Empty means every scan engine.
	Engines StringList `json:"engines,omitempty"`

	// Targets is a store.TargetOpts selector over the inventory — which
	// subjects. Carried as a map because internal/api may not import the store;
	// store.TargetOptsFrom decodes it, the same arrangement as Scan.Selector.
	Targets map[string]any `json:"targets,omitempty"`

	// Resources are globs over the resource the evidence names, which is not the
	// same question as Targets. For Prowler a finding's Host is the cloud
	// account and the resource UID is in MatchedAt, so a rule about one bucket
	// can only be said here.
	Resources StringList `json:"resources,omitempty"`

	// Templates are globs over TemplateID — the check that fired.
	Templates StringList `json:"templates,omitempty"`

	// Tags match the finding's own tags, with a ! prefix to exclude, the same
	// grammar the tag filters use.
	Tags StringList `json:"tags,omitempty"`

	Severity StringList `json:"severity,omitempty"`

	// Expr is a CEL expression over a single `finding` variable, holding the
	// finding exactly as the API renders it. It narrows and can never widen: a
	// finding the dimensions above excluded is not muted however true it is.
	Expr string `json:"expr,omitempty"`

	CreatedAt string `json:"createdAt,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

// Selects reports whether the rule names anything to mute.
//
// Engines is deliberately not counted. It narrows which runs a rule is
// considered for rather than which findings it matches, so a rule carrying only
// an engine would mute everything that engine found while reading like a
// filter. Saying that out loud takes `templates=*`.
func (m MuteRule) Selects() bool {
	return len(m.Targets) > 0 || len(m.Resources) > 0 || len(m.Templates) > 0 ||
		len(m.Tags) > 0 || len(m.Severity) > 0 || strings.TrimSpace(m.Expr) != ""
}

// Validate checks the shape of a rule. Whether its engines exist and whether
// its expression compiles are the store's business, which is where every write
// path already meets.
func (m MuteRule) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("mute rule name is required")
	}
	if !muteNamePattern.MatchString(m.Name) {
		return fmt.Errorf(
			"invalid mute rule name %q: use lowercase letters, digits and dashes, starting with a letter or digit",
			m.Name)
	}
	if !m.Selects() {
		return fmt.Errorf(
			"mute rule %s selects nothing: set at least one of targets, resources, templates, tags, severity or expr",
			m.Name)
	}
	for _, value := range m.Severity {
		if severity := ParseSeverity(value); severity == SeverityUnknown && value != string(SeverityUnknown) {
			return fmt.Errorf("mute rule %s: unknown severity %q: expected one of %v", m.Name, value, Severities())
		}
	}
	return nil
}

// Active reports whether the rule is in force.
func (m MuteRule) Active() bool { return !m.Disabled }

// AppliesTo reports whether the rule is considered for a run of this engine.
func (m MuteRule) AppliesTo(engine string) bool {
	if len(m.Engines) == 0 {
		return true
	}
	for _, name := range m.Engines {
		if name == engine {
			return true
		}
	}
	return false
}

// MutePreview reports what a rule would remove from a run that has already been
// recorded.
//
// It exists because muting drops: once a rule is in force there is no muted
// finding left in the database to inspect, so checking a rule's breadth against
// history is the only way to find out how much it takes before committing to
// it. It can only report on findings earlier runs kept.
type MutePreview struct {
	Rule string `json:"rule"`
	Scan string `json:"scan,omitempty"`

	// Matched and Examined are counts over the findings actually read, which the
	// scan filter and the limit both narrow.
	Matched  int `json:"matched"`
	Examined int `json:"examined"`

	Findings []Finding `json:"findings"`

	// Errors names expressions that failed to evaluate. A rule that errors mutes
	// nothing, so this is the difference between "matched none" and "could not
	// tell".
	Errors []string `json:"errors,omitempty"`
}

// GetID identifies a preview by the rule it describes.
func (p MutePreview) GetID() string { return p.Rule }

// GetName summarises the preview.
func (p MutePreview) GetName() string { return p.Rule }
