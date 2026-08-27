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
// show, so there is no second vocabulary to keep in step. Since the record is
// an OCSF Detection Finding, that vocabulary is OCSF's published one — an
// expression reading finding.finding_info.title or finding.resources[0].uid is
// addressing the schema rather than a recon invention.
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
// Compiled against a fully-populated exemplar rather than a zero Finding, so
// that a path the schema does not define is an error here rather than a null at
// evaluation time. gomplate installs cel's nilsafe library, which answers an
// absent path with null: against a zero Finding almost the whole schema was
// absent, so a rule with a typo in it stored successfully and then muted
// nothing, which is indistinguishable from a rule that correctly matched
// nothing.
//
// What it still cannot catch is `unmapped`, and that is deliberate: OCSF's
// escape hatch has no fixed keys, so reading into it stays dynamic and a rule
// written against one engine's extras evaluates to null on another's.
func Compile(expression string) error {
	if strings.TrimSpace(expression) == "" {
		return nil
	}

	sample, err := environment(exemplar())
	if err != nil {
		return err
	}
	compiler, err := cel.NewEnv(gomplate.CompileEnvOptions(sample, template(expression))...)
	if err != nil {
		return fmt.Errorf("build expression environment: %w", err)
	}
	compiled, issues := compiler.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("invalid expression: %w", issues.Err())
	}
	projected, ok := sample[Variable].(map[string]any)
	if !ok {
		return fmt.Errorf("project finding for compilation: %s is not an object", Variable)
	}
	return checkPaths(compiled, projected)
}
