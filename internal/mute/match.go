package mute

import (
	"strings"

	"github.com/flanksource/commons/collections"

	"github.com/flanksource/recon/internal/api"
)

// Rule is one stored rule with its target scope already resolved.
//
// Resolving the inventory selector once, when the run starts, is deliberate:
// the set of targets a rule covers is whatever it covered when the scan began,
// not whatever it happens to cover half an hour later when the scan ends.
type Rule struct {
	api.MuteRule

	// Targets are the inventory identities the rule's selector resolved to.
	// Nil when the rule carries no target selector, which means every target —
	// distinct from an empty non-nil set, which means the selector matched
	// nothing and so the rule can never apply.
	Targets []string
}

// Scoped reports whether the rule constrains which subjects it covers.
func (r Rule) Scoped() bool { return r.Targets != nil }

// Matches reports whether the rule mutes one finding, and whether it could tell.
//
// A rule that could not be evaluated reports false with an error rather than a
// bare false: "this rule does not match" and "this rule could not be checked"
// are different answers, and only the first is a reason to keep a finding
// quietly. The caller keeps the finding either way — a suppression that cannot
// be verified must never suppress — but records the second.
func (r Rule) Matches(finding api.Finding) (bool, error) {
	if !r.structurallyMatches(finding) {
		return false, nil
	}
	// Last, and only over findings the columns already selected: the expression
	// narrows what the structured scope admitted and can never widen it, which
	// is what keeps "what could this rule possibly match" answerable without
	// running anything.
	if expression := strings.TrimSpace(r.Expr); expression != "" {
		return evaluate(expression, finding)
	}
	return true, nil
}

// structurallyMatches applies every dimension the database can hold.
//
// Dimensions are ANDed and the values within one are ORed, which is what
// TargetOpts already documents. An empty dimension is unconstrained rather than
// unsatisfiable — an empty severity list means severity is not part of this
// rule, not that no severity qualifies.
func (r Rule) structurallyMatches(finding api.Finding) bool {
	switch {
	case r.Scoped() && !contains(r.Targets, finding.TargetID):
		return false
	case !matchesAny(r.Resources, resourcesOf(finding)):
		return false
	case !collections.MatchItems(finding.TemplateID, r.Templates...):
		return false
	case !matchesTags(r.Tags, finding.Tags):
		return false
	case !matchesSeverity(r.Severity, finding.Severity):
		return false
	default:
		return true
	}
}

// resourcesOf is where a finding says which thing it is about.
//
// Both, because the engines do not agree and neither one alone is the resource.
// Prowler puts the cloud account in Host and the resource uid in MatchedAt;
// nuclei puts the hostname in Host and the matched URL in MatchedAt. A rule
// naming a bucket has to reach the first, and a rule naming a host the second.
func resourcesOf(finding api.Finding) []string {
	return []string{finding.MatchedAt, finding.Host}
}

// matchesAny applies patterns to a set of values, where matching any one of
// them is a match. Used where the finding offers more than one name for the
// same thing.
func matchesAny(patterns []string, values []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, value := range values {
		if value != "" && collections.MatchItems(value, patterns...) {
			return true
		}
	}
	return false
}

// matchesTags applies the tag patterns to the finding's whole tag set.
//
// A negated pattern excludes the finding outright rather than being ignored
// because some other tag matched: `!db-vendor` has to skip a finding tagged both
// `db` and `db-vendor`. The same rule, and the same reasoning, as the template
// listing's tag filter.
func matchesTags(patterns, tags []string) bool {
	if len(patterns) == 0 {
		return true
	}
	// An untagged finding still has to survive an exclusion-only filter: it is
	// not tagged `db-vendor`, so `!db-vendor` is not about it.
	if len(tags) == 0 {
		return collections.MatchItems("", patterns...)
	}
	matched, negated := collections.MatchAny(tags, patterns...)
	return matched && !negated
}

func matchesSeverity(wanted []string, severity api.Severity) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, value := range wanted {
		if api.ParseSeverity(value) == severity {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
