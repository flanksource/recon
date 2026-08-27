package api

import (
	"fmt"
	"strings"

	clickyapi "github.com/flanksource/clicky/api"
)

// The preflight is the whole point of a dry run, so it is rendered as one:
// what would land, where, and — the two questions a summary line cannot answer —
// which identities nobody can decide between and which findings the catalog does
// not claim at all. Both lists are bounded here and only here; the JSON carries
// every row, and what was left off the terminal is stated rather than trimmed
// away quietly.
const (
	prettyConfigLimit     = 25
	prettyUnresolvedLimit = 20
)

// Pretty renders the sync preflight.
func (u InsightSync) Pretty() clickyapi.Text {
	text := clickyapi.Text{}.AddText(u.headline(), "font-bold").NewLine()
	for _, line := range u.summary() {
		text = text.AddText(line, "muted").NewLine()
	}
	if len(u.Configs) > 0 {
		text = text.NewLine().AddText("Config items", "font-bold").NewLine().
			Add(clickyapi.NewTableFrom(head(u.Configs, prettyConfigLimit))).
			Add(more(len(u.Configs), prettyConfigLimit, "config items"))
	}
	if len(u.Ambiguous) > 0 {
		text = text.NewLine().Add(ambiguousText(u.Ambiguous))
	}
	if len(u.Unresolved) > 0 {
		text = text.NewLine().
			AddText("Not synced — nothing in the catalog carries these identities", "font-bold").NewLine().
			Add(clickyapi.NewTableFrom(head(u.Unresolved, prettyUnresolvedLimit))).
			Add(more(len(u.Unresolved), prettyUnresolvedLimit, "unresolved states"))
	}
	return text
}

func (u InsightSync) headline() string {
	verb := "sync"
	if u.DryRun {
		verb = "preview"
	}
	headline := verb + " insights"
	if u.Server != "" {
		headline += " → " + u.Server
	}
	return headline + " as " + u.Agent
}

func (u InsightSync) summary() []string {
	attached := u.Direct + u.RolledUp
	lines := []string{
		fmt.Sprintf("%d states over %d resources · %d eligible · %d skipped",
			u.MatchedStates, u.MatchedResources, u.Eligible, u.Skipped),
		fmt.Sprintf("%d attached to %d config items · %d direct · %d rolled up · %d pinned",
			attached, len(u.Configs), u.Direct, u.RolledUp, u.Pinned),
		fmt.Sprintf("%d open · %d resolved · %d silenced", u.Open, u.Resolved, u.Silenced),
	}
	if u.Pushed > 0 {
		lines = append(lines, fmt.Sprintf("%d insights pushed", u.Pushed))
	}
	if len(u.Ambiguous) > 0 || len(u.Unresolved) > 0 {
		lines = append(lines, fmt.Sprintf("%d ambiguous identities · %d unresolved states",
			len(u.Ambiguous), len(u.Unresolved)))
	}
	return lines
}

// ambiguousText lists each undecided identity above the config items it could
// attach to, with the flag that decides it. A table would put the ids that make
// the choice into one cramped cell; this is the one section whose purpose is to
// be acted on rather than read.
func ambiguousText(items []InsightAmbiguity) clickyapi.Text {
	text := clickyapi.Text{}.
		AddText("Matched more than one config item — nothing was attached to these", "font-bold").NewLine()
	for _, item := range items {
		text = text.AddText(fmt.Sprintf("%s — %d states", item.Identity, item.States), "warning")
		if len(item.Resources) > 0 {
			text = text.AddText(" ("+strings.Join(item.Resources, ", ")+")", "muted")
		}
		text = text.NewLine()
		for _, option := range item.Options {
			text = text.AddText("    "+describeChoice(option), "muted").NewLine()
		}
		text = text.AddText(fmt.Sprintf("    choose with --config %s=<config-id>", item.Identity), "muted").NewLine()
	}
	return text
}

func describeChoice(option InsightChoice) string {
	described := option.ID + "  " + option.Name
	if option.Type != "" {
		described += "  " + option.Type
	}
	for _, note := range []struct {
		set  bool
		text string
	}{
		{option.Ancestor, "contains the matches"},
		{option.Root, "root"},
		{option.Deleted, "deleted"},
	} {
		if note.set {
			described += "  [" + note.text + "]"
		}
	}
	return described
}

func more(total, shown int, noun string) clickyapi.Text {
	if total <= shown {
		return clickyapi.Text{}
	}
	return clickyapi.Text{}.AddText(fmt.Sprintf("… and %d more %s, in the JSON output", total-shown, noun), "muted").NewLine()
}

func head[T any](items []T, limit int) []T {
	if len(items) <= limit {
		return items
	}
	return items[:limit]
}

func (c InsightConfig) Columns() []clickyapi.ColumnDef {
	return []clickyapi.ColumnDef{
		{Name: "name", Label: "Name"},
		{Name: "type", Label: "Type"},
		{Name: "insights", Label: "Insights"},
		{Name: "attached", Label: "Attached"},
	}
}

func (c InsightConfig) Row() map[string]any {
	attached := "direct"
	if c.RolledUp {
		attached = "rolled up"
	}
	if c.Pinned {
		attached += ", chosen"
	}
	return map[string]any{
		"name":     orID(c.Name, c.ID),
		"type":     c.Type,
		"insights": c.Insights,
		"attached": attached,
	}
}

func (u InsightUnresolved) Columns() []clickyapi.ColumnDef {
	return []clickyapi.ColumnDef{
		{Name: "host", Label: "Resource"},
		{Name: "severity", Label: "Severity"},
		{Name: "finding", Label: "Finding"},
		{Name: "reason", Label: "Reason"},
	}
}

func (u InsightUnresolved) Row() map[string]any {
	return map[string]any{
		"host":     u.Host,
		"severity": string(u.Severity),
		"finding":  u.Finding,
		"reason":   u.Reason,
	}
}

func orID(name, id string) string {
	if name == "" {
		return id
	}
	return name
}
