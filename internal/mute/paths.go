package mute

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
)

// dynamic marks a node below which any path is legal.
//
// OCSF's `unmapped` and the json_t evidence payloads have no fixed keys by
// definition, so a rule reading into one cannot be checked and must not be
// rejected. The exemplar plants this key in every such node, and the walk stops
// the moment it sees one.
const dynamic = "*"

// checkPaths rejects an expression that reads an attribute the schema does not
// define.
//
// gomplate declares every environment variable as cel.AnyType, so CEL itself
// type-checks nothing below `finding` — every path compiles, and cel's nilsafe
// library then answers the ones that do not exist with null. A rule with a typo
// in it therefore stored successfully and muted nothing, which is exactly what
// a rule that correctly matches nothing looks like.
//
// So the paths are checked here instead, against the JSON projection of a
// finding with every modelled attribute present. The shortest failing prefix is
// what gets reported: it names the step where the path left the schema, rather
// than the whole expression.
func checkPaths(ast *cel.Ast, document map[string]any) error {
	var unknown []string
	seen := map[string]bool{}

	celast.PostOrderVisit(ast.NativeRep().Expr(), celast.NewExprVisitor(func(node celast.Expr) {
		steps, addressable := selectPath(node)
		if !addressable || steps[0] != Variable {
			return
		}
		if known(document, steps[1:]) {
			return
		}
		// Only the shortest failing prefix. Every longer path through the same
		// bad step fails too, and reporting all of them buries the one that
		// matters.
		rendered := render(steps)
		for _, existing := range unknown {
			if strings.HasPrefix(rendered, existing) {
				return
			}
		}
		if !seen[rendered] {
			seen[rendered] = true
			unknown = append(unknown, rendered)
		}
	}))

	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("unknown finding attribute %s: a rule reads the OCSF Detection Finding schema",
		strings.Join(quoted(unknown), ", "))
}

// selectPath renders a chain of field selections as the steps it addresses,
// with "[]" standing for an index. It reports false for anything that is not
// one — a literal, a function call, a presence test.
func selectPath(node celast.Expr) ([]string, bool) {
	switch node.Kind() {
	case celast.IdentKind:
		return []string{node.AsIdent()}, true
	case celast.SelectKind:
		selected := node.AsSelect()
		// has(finding.x) is a presence test, whose whole purpose is asking about
		// an attribute that may be absent.
		if selected.IsTestOnly() {
			return nil, false
		}
		parent, addressable := selectPath(selected.Operand())
		if !addressable {
			return nil, false
		}
		return append(parent, selected.FieldName()), true
	case celast.CallKind:
		call := node.AsCall()
		if call.FunctionName() != operators.Index || len(call.Args()) != 2 {
			return nil, false
		}
		parent, addressable := selectPath(call.Args()[0])
		if !addressable {
			return nil, false
		}
		return append(parent, "[]"), true
	default:
		return nil, false
	}
}

// known walks the exemplar the way the expression walks a finding.
func known(document any, steps []string) bool {
	current := document
	for _, step := range steps {
		switch node := current.(type) {
		case map[string]any:
			if _, free := node[dynamic]; free {
				return true
			}
			next, present := node[step]
			if !present {
				return false
			}
			current = next
		case []any:
			if step != "[]" || len(node) == 0 {
				return false
			}
			current = node[0]
		default:
			return false
		}
	}
	return true
}

func render(steps []string) string {
	rendered := steps[0]
	for _, step := range steps[1:] {
		if step == "[]" {
			rendered += "[]"
			continue
		}
		rendered += "." + step
	}
	return rendered
}

func quoted(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strconv.Quote(value))
	}
	return out
}
