package mute

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/flanksource/gomplate/v3"
	"github.com/google/cel-go/cel"

	"github.com/flanksource/recon/internal/api"
)

// Variable is the single name a mute expression is written against.
//
// One variable, and never a custom function, is a hard requirement rather than
// a style choice. gomplate caches a compiled program under a key derived from
// the environment's variable *names* plus the expression, and declines to cache
// at all when a template carries its own Functions or CelEnvs. A fixed
// one-variable environment therefore compiles once per rule per process and
// hits the cache for every finding after; anything else silently recompiles the
// expression for every finding in the run.
const Variable = "finding"

// environment renders one finding the way an expression author sees it.
//
// The JSON projection rather than the Go struct: an expression is written
// against what `finding get --json`, the REST payload and findings.jsonl all
// show, so there is no second vocabulary to keep in step. `finding.raw` is what
// earns CEL its place — the engine's own record is the only place a resource's
// native identity survives in full.
func environment(finding api.Finding) (map[string]any, error) {
	encoded, err := json.Marshal(finding)
	if err != nil {
		return nil, fmt.Errorf("project finding for evaluation: %w", err)
	}
	var projected map[string]any
	if err := json.Unmarshal(encoded, &projected); err != nil {
		return nil, fmt.Errorf("project finding for evaluation: %w", err)
	}
	return map[string]any{Variable: projected}, nil
}

// template builds the expression gomplate runs.
//
// CacheKey is deliberately left unset. gomplate uses an explicit key verbatim,
// so keying on the rule's name would make an edited expression keep running the
// program compiled from the old one.
func template(expression string) gomplate.Template {
	return gomplate.Template{Expression: expression}
}

// evaluate reports whether an expression matches one finding.
func evaluate(expression string, finding api.Finding) (bool, error) {
	env, err := environment(finding)
	if err != nil {
		return false, err
	}
	return gomplate.RunTemplateBool(env, template(expression))
}

// Compile checks that an expression is usable before it is stored.
//
// Compiling rather than evaluating, so the CEL issue's source position survives
// into the message — RunTemplateBool's error does not carry one. It catches
// syntax errors and unknown identifiers.
//
// It cannot catch everything, and what it misses is worth knowing. gomplate
// installs cel's nilsafe library with zero values, so reading a key a finding
// does not carry yields null instead of failing: a rule written against one
// engine's raw record quietly matches nothing on another engine's findings
// rather than erroring. What survives to evaluation time is the genuine
// failures — an expression that does not answer yes or no, a bad conversion, a
// bad regex — and a rule that hits one of those mutes nothing.
func Compile(expression string) error {
	if strings.TrimSpace(expression) == "" {
		return nil
	}

	sample, err := environment(api.Finding{})
	if err != nil {
		return err
	}
	compiler, err := cel.NewEnv(gomplate.CompileEnvOptions(sample, template(expression))...)
	if err != nil {
		return fmt.Errorf("build expression environment: %w", err)
	}
	if _, issues := compiler.Compile(expression); issues != nil && issues.Err() != nil {
		return fmt.Errorf("invalid expression: %w", issues.Err())
	}
	return nil
}
