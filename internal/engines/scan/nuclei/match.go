package nuclei

import (
	"path/filepath"
	"sort"
	"strings"

	nucleiconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/index"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	templatetypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// PreviewLimit bounds the templates a preview carries. The counts describe the
// whole match; the list is a sample, because 4,314 rows is not a preview.
const PreviewLimit = 200

// Preview is what a profile would run.
type Preview struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
	ByType     map[string]int `json:"byType"`
	ByTag      []TagCount     `json:"byTag"`

	// MaxRequests is the summed per-template request cost, which is the closest
	// thing to "how big is this scan" available before running it. Templates
	// that do not declare one contribute nothing, so it is a lower bound.
	MaxRequests int `json:"maxRequests"`

	Templates []Template `json:"templates"`
	Truncated bool       `json:"truncated"`

	// Unsupported names the configured filters this preview could not evaluate.
	// A count computed while ignoring a filter is an upper bound, and saying so
	// is the difference between a preview and a guess.
	Unsupported []string `json:"unsupported,omitempty"`
}

// TagCount is one tag and how many matched templates carry it.
type TagCount struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// TopTags bounds the tag breakdown. Enough to characterise a selection without
// returning the whole vocabulary, which for an unfiltered profile is thousands.
const TopTags = 25

// Match reports which templates a profile configuration selects.
//
// The filter is nuclei's own, so tag, severity, protocol and id precedence —
// including include-tags overriding an exclusion — is upstream behaviour rather
// than a second implementation of it that can drift. What this adds is the part
// index.Filter does not model: which directories were selected, and which
// capabilities the loader requires before it will accept a template at all.
func (i *Index) Match(config map[string]any) Preview {
	selected := i.Select(config)

	preview := Preview{
		Total:      len(selected),
		BySeverity: map[string]int{},
		ByType:     map[string]int{},
		Templates:  selected[:min(len(selected), PreviewLimit)],
		Truncated:  len(selected) > PreviewLimit,
	}

	tags := map[string]int{}
	for _, template := range selected {
		preview.BySeverity[template.Severity]++
		preview.ByType[template.ProtocolType]++
		preview.MaxRequests += template.MaxRequests
		for _, tag := range template.Tags {
			tags[tag]++
		}
	}
	preview.ByTag = topTags(tags)
	preview.Unsupported = unsupported(config, selected)
	return preview
}

// unsupported names the reasons a count may overstate what will run.
//
// Both are real and neither is knowable from the templates alone, so the honest
// thing is to say so rather than to quietly report a number that a scan will not
// match.
func unsupported(config map[string]any, selected []Template) []string {
	var reasons []string

	if _, ok := config["template-condition"]; ok {
		// A DSL expression evaluated against each template's metadata. Treating
		// it as matching everything is the only option that cannot understate.
		reasons = append(reasons,
			"template-condition is not evaluated, so this is an upper bound")
	}

	if boolValue(config, "code") {
		for _, template := range selected {
			if template.Requires.Code {
				// A code template runs through an interpreter — powershell,
				// python, bash. Nuclei drops the ones whose interpreter is
				// missing when it loads them, and which are installed is a fact
				// about the scanning host, not about the templates.
				reasons = append(reasons,
					"code templates also need their interpreter installed on the scanning host")
				break
			}
		}
	}
	return reasons
}

// Select returns every template a configuration selects, in path order.
//
// This is the whole answer, not the preview's sample: the template browser
// pages through it, and a count that disagreed with the list it summarises
// would be worse than either alone.
func (i *Index) Select(config map[string]any) []Template {
	filter := buildFilter(config)
	roots := templateRoots(i.Root, config)
	caps := capabilities(config)

	var selected []Template
	for _, template := range i.Templates {
		if underRoots(template.FilePath, roots) && caps.allows(template) && filter.Matches(template.Metadata) {
			selected = append(selected, template)
		}
	}
	return selected
}

// buildFilter translates a profile into nuclei's template filter.
//
// The forced excludes are appended here for the same reason Options appends
// them: a preview has to describe the scan that would run, and that scan never
// includes a denial-of-service template.
func buildFilter(config map[string]any) *index.Filter {
	// nuclei keeps its own deny-list — tags such as txt-service, and the
	// individual templates whose matchers are known to produce false positives.
	// It applies to every scan unless a run asks for those tags by name, so a
	// preview that skipped it would promise templates the scan then drops.
	ignore := nucleiconfig.ReadIgnoreFile()

	filter := &index.Filter{
		Authors:          list(config, "author"),
		Tags:             list(config, "tags"),
		ExcludeTags:      concat(list(config, "exclude-tags"), excludedTags, ignore.Tags),
		IncludeTags:      list(config, "include-tags"),
		IDs:              list(config, "template-id"),
		ExcludeIDs:       list(config, "exclude-id"),
		IncludeTemplates: list(config, "include-templates"),
		ExcludeTemplates: concat(list(config, "exclude-templates"), ignoredTemplates()),
	}
	filter.Severities = severityList(config, "severity")
	filter.ExcludeSeverities = severityList(config, "exclude-severity")
	filter.ProtocolTypes = protocolList(config, "type")
	filter.ExcludeProtocolTypes = protocolList(config, "exclude-type")
	return filter
}

// severityList parses a configured severity list with nuclei's own vocabulary,
// so "moderate" is rejected here exactly as it would be by the scanner.
func severityList(config map[string]any, key string) severity.Severities {
	var parsed severity.Severities
	for _, value := range list(config, key) {
		_ = parsed.Set(value)
	}
	return parsed
}

func protocolList(config map[string]any, key string) templatetypes.ProtocolTypes {
	var parsed templatetypes.ProtocolTypes
	for _, value := range list(config, key) {
		_ = parsed.Set(value)
	}
	return parsed
}

// granted is the set of capabilities a configuration opts into.
type granted struct {
	Capabilities
	dast bool
}

func capabilities(config map[string]any) granted {
	return granted{
		Capabilities: Capabilities{
			Headless:      boolValue(config, "headless"),
			Code:          boolValue(config, "code"),
			File:          boolValue(config, "file"),
			SelfContained: boolValue(config, "enable-self-contained"),
			Fuzzing:       boolValue(config, "dast"),
		},
		dast: boolValue(config, "dast"),
	}
}

// allows mirrors the loader's capability gate: a template needing something the
// configuration did not opt into is never loaded, however well it matches the
// metadata filters.
func (g granted) allows(template Template) bool {
	needs := template.Requires
	switch {
	case needs.Headless && !g.Headless:
		return false
	case needs.Code && !g.Code:
		return false
	case needs.File && !g.File:
		return false
	case needs.SelfContained && !g.SelfContained:
		return false
	case needs.Fuzzing && !g.Fuzzing:
		return false
	}

	// DAST does not widen a scan, it replaces it: with -dast nuclei runs only
	// the templates that fuzz.
	if g.dast && !needs.Fuzzing {
		return false
	}
	return true
}

// templateRoots resolves the directories a profile selected, as nuclei resolves
// them: relative to the templates directory unless already absolute. No entry
// means the whole corpus.
func templateRoots(root string, config map[string]any) []string {
	selected := append(list(config, "templates"), list(config, "workflows")...)
	if len(selected) == 0 {
		return nil
	}

	roots := make([]string, 0, len(selected))
	for _, entry := range selected {
		if !filepath.IsAbs(entry) {
			entry = filepath.Join(root, entry)
		}
		roots = append(roots, filepath.Clean(entry))
	}
	return roots
}

func underRoots(path string, roots []string) bool {
	if len(roots) == 0 {
		return true
	}
	for _, root := range roots {
		if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// topTags returns the most common tags, ties broken alphabetically so the same
// selection always renders the same way.
func topTags(counts map[string]int) []TagCount {
	tags := make([]TagCount, 0, len(counts))
	for tag, count := range counts {
		tags = append(tags, TagCount{Tag: tag, Count: count})
	}
	sort.Slice(tags, func(i, j int) bool {
		if tags[i].Count != tags[j].Count {
			return tags[i].Count > tags[j].Count
		}
		return tags[i].Tag < tags[j].Tag
	})
	return tags[:min(len(tags), TopTags)]
}

func concat(lists ...[]string) []string {
	var joined []string
	for _, list := range lists {
		joined = append(joined, list...)
	}
	return joined
}

func list(config map[string]any, key string) []string {
	value, ok := config[key]
	if !ok {
		return nil
	}
	items, err := asStrings(value)
	if err != nil {
		return nil
	}
	return items
}

func boolValue(config map[string]any, key string) bool {
	enabled, _ := config[key].(bool)
	return enabled
}
