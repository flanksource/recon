package mute

import "strings"

// Dimension names the one thing a rule selects on, when it selects on exactly
// one. An engine can only ever express a single-dimension rule natively.
type Dimension string

const (
	// DimensionTemplates is the check that fired.
	DimensionTemplates Dimension = "templates"
	// DimensionTags is the finding's own tags.
	DimensionTags Dimension = "tags"
	// DimensionSeverity is the severity ladder.
	DimensionSeverity Dimension = "severity"

	// DimensionNone is a rule no engine can express.
	DimensionNone Dimension = ""
)

// Plan records which rules an engine took on before the run started.
type Plan struct {
	// PushedDown maps a rule name to the engine option that expresses it. A
	// rule listed here is not applied to the results: the findings it would
	// have matched were never produced.
	PushedDown map[string]string
}

// Pushed reports whether the engine took this rule on.
func (p Plan) Pushed(name string) bool {
	_, pushed := p.PushedDown[name]
	return pushed
}

// Deferred returns the rules that still have to be applied to the results.
func (p Plan) Deferred(rules []Rule) []Rule {
	if len(p.PushedDown) == 0 {
		return rules
	}
	deferred := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if !p.Pushed(rule.Name) {
			deferred = append(deferred, rule)
		}
	}
	return deferred
}

// dimensions is the fixed order Pushable inspects, so a rule that somehow set
// two is reported the same way every time.
var dimensions = []Dimension{DimensionTemplates, DimensionTags, DimensionSeverity}

// Pushable reports the single dimension an engine could express for this rule,
// or DimensionNone when it could express nothing.
//
// The asymmetry this guards is easy to miss and expensive to get wrong. An
// engine's exclusions are a union — `-exclude-id X -exclude-severity high`
// drops template X entirely *and* everything high — while a rule's dimensions
// are an intersection. Pushing a two-dimension rule down would suppress
// findings the rule does not cover, and because the checks never run those
// findings never exist to notice. So a rule is pushable only when there is
// nothing to intersect:
//
//   - it carries no expression, which no engine can evaluate;
//   - it scopes no targets and no resources, because an engine's exclusions
//     apply to the whole invocation rather than to one subject;
//   - exactly one of templates, tags and severity is set;
//   - and none of that dimension's values is negated, because an exclusion list
//     cannot say "everything not carrying this".
func (r Rule) Pushable() Dimension {
	if strings.TrimSpace(r.Expr) != "" || r.Scoped() || len(r.Resources) > 0 {
		return DimensionNone
	}

	found := DimensionNone
	for _, dimension := range dimensions {
		values := r.Values(dimension)
		if len(values) == 0 {
			continue
		}
		if found != DimensionNone || negated(values) {
			return DimensionNone
		}
		found = dimension
	}
	return found
}

// Values returns the rule's values for one dimension.
func (r Rule) Values(dimension Dimension) []string {
	switch dimension {
	case DimensionTemplates:
		return r.Templates
	case DimensionTags:
		return r.Tags
	case DimensionSeverity:
		return r.Severity
	default:
		return nil
	}
}

func negated(values []string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, "!") {
			return true
		}
	}
	return false
}
