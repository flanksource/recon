// Package mute decides which findings an operator has already accepted.
//
// A rule selects findings by the subjects it covers, the resource the evidence
// names, the check that fired, its tags and its severity, optionally narrowed
// by a CEL expression. Dimensions are ANDed and the values within one are ORed.
// An empty dimension is unconstrained; a rule that constrains nothing is
// refused when it is stored, so an accidentally universal mute cannot be built.
//
// Two things happen to a matching finding, and which one depends on the engine.
// Where the engine can express the same exclusion natively the check is never
// run — that is the only form of muting that saves any time — and where it
// cannot, the finding is dropped from the run before it is recorded. Either
// way the run's mutes.json says which rule was responsible, because the
// dropped rows are not in the database to ask.
//
// Nothing here reads the database or the network. Apply is a pure function over
// findings so that the run path and `mute preview` are the same code rather
// than two matchers that agree until they do not.
package mute

import (
	"fmt"

	"github.com/flanksource/recon/internal/api"
)

// Result is what applying a set of rules to a run produced.
type Result struct {
	// Kept are the findings the run records, in the order the engine reported
	// them, each carrying the line of the engine's own output it came from.
	Kept []api.Finding

	// Muted counts the findings removed. Checks a rule stopped from running are
	// not counted: they produced nothing to count.
	Muted int

	// ByRule maps a rule name to the lines of the engine's findings file it
	// removed. This is the only surviving record of what a run dropped, so it
	// addresses the artifact rather than the database — the muted rows are not
	// in the database to point at.
	ByRule map[string][]int

	// Errors names rules that could not be evaluated, once each however many
	// findings they saw. A rule that errors mutes nothing, so this is the
	// difference between "matched none" and "could not tell".
	Errors map[string]string
}

// Apply removes the findings the rules match.
//
// Every kept finding is stamped with the line it occupied in the engine's own
// output, so line_no continues to address findings.jsonl even though the rows
// between are gone. That correspondence is what lets someone read a run's
// directory a month later, with no database, and see exactly what was removed.
// It is stamped unconditionally — including when no rule is in force — so there
// is one numbering rule rather than one for muted runs and another for clean
// ones.
func Apply(rules []Rule, findings []api.Finding) Result {
	result := Result{
		Kept:   make([]api.Finding, 0, len(findings)),
		ByRule: map[string][]int{},
		Errors: map[string]string{},
	}

	for index, finding := range findings {
		line := index + 1
		finding.LineNo = line

		if rule, matched := firstMatch(rules, finding, result.Errors); matched {
			result.Muted++
			result.ByRule[rule] = append(result.ByRule[rule], line)
			continue
		}
		result.Kept = append(result.Kept, finding)
	}
	return result
}

// firstMatch returns the name of the first rule that mutes a finding.
//
// First rather than all: a finding is muted once, and attributing it to one
// rule makes mutes.json readable. Rules are applied in the order given, which
// the store returns by name, so the attribution is stable across runs rather
// than depending on how the rows happened to come back.
func firstMatch(rules []Rule, finding api.Finding, errors map[string]string) (string, bool) {
	for _, rule := range rules {
		matched, err := rule.Matches(finding)
		if err != nil {
			// Recorded once per rule, not once per finding: a broken expression
			// in a large scan is worth saying, and saying it ten thousand times
			// would bury every real finding. The finding is kept — a mute that
			// cannot be evaluated must never suppress.
			if _, reported := errors[rule.Name]; !reported {
				errors[rule.Name] = err.Error()
			}
			continue
		}
		if matched {
			return rule.Name, true
		}
	}
	return "", false
}

// Summary renders one line for the run log.
func (r Result) Summary(rules []Rule) string {
	if len(rules) == 0 {
		return "mute: no rules in force"
	}
	summary := fmt.Sprintf("mute: %d rule(s) in force, %d finding(s) dropped", len(rules), r.Muted)
	if len(r.Errors) > 0 {
		summary += fmt.Sprintf(", %d rule(s) could not be evaluated", len(r.Errors))
	}
	return summary
}
