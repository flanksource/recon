package scan

import (
	"context"
	"fmt"
	"sort"

	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/mute"
	"github.com/flanksource/recon/internal/store"
)

// describeTargets renders a rule's inventory scope as the sentence the selector
// already knows how to write, so a run's record explains itself.
func describeTargets(rule mute.Rule) string {
	if len(rule.Targets) == 0 && !rule.Scoped() {
		return ""
	}
	opts, err := store.TargetOptsFrom(rule.MuteRule.Targets)
	if err != nil {
		return ""
	}
	if opts.Empty() {
		return ""
	}
	return opts.Describe()
}

// MuteRecord is what a run says about the rules that were in force.
//
// Written whether or not anything was muted: "no rule matched" and "no rule
// existed" are different facts about a run, and a reader with only the
// database cannot tell them apart, because a muted finding leaves no row.
type MuteRecord struct {
	// Rules is every rule the run considered, in the order they were applied.
	Rules []MuteRuleRecord `json:"rules"`

	// Muted counts findings removed after the engine reported them. Checks a
	// rule stopped from running are not counted here — nothing was produced to
	// count — and the rule's own disposition says so instead.
	Muted int `json:"muted"`
}

// MuteRuleRecord is one rule's effect on one run.
type MuteRuleRecord struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`

	// Scope is the rule's target selector as a sentence, so the record explains
	// itself without the reader reconstructing a selector.
	Scope string `json:"scope,omitempty"`

	// Disposition is how the rule took effect: `pushed-down` when the engine was
	// told not to run the check at all, `applied` when matching findings were
	// removed afterwards.
	Disposition string `json:"disposition"`

	// Mechanism names the engine option a pushed-down rule became.
	Mechanism string `json:"mechanism,omitempty"`

	// Lines are the lines of findings.jsonl this rule removed. Empty for a
	// pushed-down rule, which produced no line to remove.
	Lines []int `json:"lines,omitempty"`

	// Error says why a rule could not be evaluated. A rule that errors mutes
	// nothing, so this is the difference between "removed none" and "could not
	// tell".
	Error string `json:"error,omitempty"`
}

// muteRules loads the rules in force for a run.
//
// Resolved when the run is queued rather than when it finishes: a scan takes
// minutes, and a rule should cover what it covered when the operator started
// the run.
func (r *Runtime) muteRules(ctx context.Context, engine string, request Request) ([]mute.Rule, error) {
	if request.NoMutes {
		return nil, nil
	}
	rules, err := r.Store.MuteRules(ctx, engine)
	if err != nil {
		return nil, fmt.Errorf("load mute rules: %w", err)
	}
	return rules, nil
}

// offerMutes gives the engine the chance to enforce what it can itself.
//
// The configuration is validated again afterwards. An engine appends to its own
// exclusion options here, and a merge that produced something its catalog would
// reject has to fail the request rather than a scan halfway through — the same
// contract resolveConfig holds the profile and the overrides to.
func offerMutes(
	engine enginescan.Engine,
	spec engines.Spec,
	config map[string]any,
	workDir string,
	rules []mute.Rule,
) (enginescan.Pushdown, error) {
	if len(rules) == 0 {
		return enginescan.Pushdown{}, nil
	}

	muter, capable := engine.(enginescan.Muter)
	if !capable {
		// Not every engine can decline to run a check — InSpec's profile option
		// is an allow-list with no exclusion at all. Its rules are applied to
		// the results instead, and the run's mutes.json says so.
		return enginescan.Pushdown{}, nil
	}

	pushdown, err := muter.Pushdown(enginescan.PushdownRequest{
		Config: config, WorkDir: workDir, Rules: rules,
	})
	if err != nil {
		return enginescan.Pushdown{}, fmt.Errorf("apply mute rules to the %s configuration: %w", spec.Name, err)
	}
	if err := spec.ValidateConfig(config); err != nil {
		return enginescan.Pushdown{}, fmt.Errorf("mute rules produced an invalid %s configuration: %w", spec.Name, err)
	}
	return pushdown, nil
}

// muteRecord builds the run's account of what its rules did.
func muteRecord(rules []mute.Rule, plan mute.Plan, result mute.Result) MuteRecord {
	record := MuteRecord{Rules: make([]MuteRuleRecord, 0, len(rules)), Muted: result.Muted}

	for _, rule := range rules {
		entry := MuteRuleRecord{
			Name:        rule.Name,
			Comment:     rule.Comment,
			Scope:       describeTargets(rule),
			Disposition: "applied",
			Lines:       result.ByRule[rule.Name],
			Error:       result.Errors[rule.Name],
		}
		if mechanism, pushed := plan.PushedDown[rule.Name]; pushed {
			entry.Disposition = "pushed-down"
			entry.Mechanism = mechanism
			entry.Lines = nil
		}
		record.Rules = append(record.Rules, entry)
	}

	sort.Slice(record.Rules, func(i, j int) bool { return record.Rules[i].Name < record.Rules[j].Name })
	return record
}
