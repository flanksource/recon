package entities

import (
	"context"
	"sort"
	"strings"

	"github.com/flanksource/clicky"
	clickyapi "github.com/flanksource/clicky/api"
	"github.com/flanksource/commons/logger"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/discovery"
	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/store"
)

// Filters are what a listing can be narrowed by, declared once per entity.
//
// Declaring them is not decoration: clicky marks every query parameter of a
// list that carries filters as a filter control, and answers the option sets
// from the same declaration that the shell completes against. Without them the
// generated API describes nine parameters and says nothing about any of them,
// which is what the UI had to work around by loading the whole inventory and
// filtering it in the browser.

// values resolves a filter's option set.
//
// Per request rather than at registration: a tag added a minute ago has to be
// offerable now, and the database is not open when the command tree is built.
type values func(context.Context) []string

// filter offers the values one field can take.
//
// The interface is generic in the options struct but this implementation never
// reads it — each filter enumerates its whole vocabulary and lets clicky narrow
// it against what the user typed. Selected values are their own labels (a tag, a
// class and a host all read as themselves), so Lookup adds nothing.
type filter[Opts any] struct {
	key    string
	label  string
	values values
}

func (f filter[Opts]) Key() string   { return f.key }
func (f filter[Opts]) Label() string { return f.label }

func (f filter[Opts]) Lookup(*Opts) (map[string]clickyapi.Textable, error) { return nil, nil }

func (f filter[Opts]) Options(opts Opts) map[string]clickyapi.Textable {
	return f.OptionsWithContext(context.Background(), opts)
}

// OptionsWithContext is the variant clicky prefers when serving a request, and
// the only one that can reach a database opened per request.
func (f filter[Opts]) OptionsWithContext(ctx context.Context, _ Opts) map[string]clickyapi.Textable {
	return textable(f.values(ctx))
}

func (f filter[Opts]) OptionsWithQuery(opts Opts, query string, limit int) (map[string]clickyapi.Textable, int) {
	return f.OptionsWithQueryAndContext(context.Background(), opts, query, limit)
}

// OptionsWithQueryAndContext narrows the vocabulary where it is known rather
// than in the browser.
//
// Declaring it is what makes the filter searchable, and an unsearchable filter
// is capped: clicky returns the first 200 options and nothing tells the user
// the rest exist. An inventory has more hosts than that, so without this the
// ones past the cap look like they are not in it.
func (f filter[Opts]) OptionsWithQueryAndContext(
	ctx context.Context, _ Opts, query string, limit int,
) (map[string]clickyapi.Textable, int) {
	matched := match(f.values(ctx), query)
	total := len(matched)
	if limit > 0 && len(matched) > limit {
		matched = matched[:limit]
	}
	return textable(matched), total
}

// match keeps the values containing query, case-insensitively. An empty query
// asks for the head of the set and matches everything.
func match(values []string, query string) []string {
	if query == "" {
		return values
	}
	query = strings.ToLower(query)
	matched := make([]string, 0, len(values))
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), query) {
			matched = append(matched, value)
		}
	}
	return matched
}

func textable(values []string) map[string]clickyapi.Textable {
	options := make(map[string]clickyapi.Textable, len(values))
	for _, value := range values {
		options[value] = clickyapi.Text{Content: value}
	}
	return options
}

// fixed is a vocabulary the code defines rather than the data — a class, a
// severity, a phase. It cannot go stale, so it is not worth a query.
func fixed(options ...string) values {
	return func(context.Context) []string { return options }
}

// vocabulary is a vocabulary only the database knows. A failure to read it
// leaves the control with no options rather than failing the request: the
// listing behind it makes the same query and reports the same failure, and
// losing the whole page because a dropdown could not be filled would hide it.
func (r *Registry) vocabulary(of store.Vocabulary) values {
	return func(ctx context.Context) []string {
		st, err := r.store()
		if err != nil {
			logger.Debugf("%s filter has no options: %v", of, err)
			return nil
		}
		options, err := st.Vocabulary(ctx, of)
		if err != nil {
			logger.Warnf("%s filter has no options: %v", of, err)
			return nil
		}
		return options
	}
}

// engineNames lists the registered engines of the given kinds. They come from
// the registries rather than from what has already run, because an engine that
// has never been used is still one you can ask for.
func engineNames(kinds ...string) values {
	return func(context.Context) []string {
		var names []string
		for _, kind := range kinds {
			specs := enginescan.Specs()
			if kind == api.KindDiscovery {
				specs = enginediscovery.Specs()
			}
			for _, spec := range specs {
				names = append(names, spec.Name)
			}
		}
		sort.Strings(names)
		return names
	}
}

func (r *Registry) targetFilters() []clicky.Filter[store.TargetOpts] {
	return []clicky.Filter[store.TargetOpts]{
		filter[store.TargetOpts]{key: "class", label: "Class", values: fixed(classNames()...)},
		filter[store.TargetOpts]{key: "tags", label: "Tags", values: r.vocabulary(store.TargetTags)},
		filter[store.TargetOpts]{key: "profiles", label: "Profiles", values: r.vocabulary(store.TargetProfiles)},
		filter[store.TargetOpts]{key: "hosts", label: "Host", values: r.vocabulary(store.TargetHosts)},
		filter[store.TargetOpts]{key: "ports", label: "Port", values: r.vocabulary(store.TargetPorts)},
		filter[store.TargetOpts]{key: "status", label: "HTTP status", values: r.vocabulary(store.TargetStatus)},
	}
}

func (r *Registry) scanFilters() []clicky.Filter[store.ScanOpts] {
	return []clicky.Filter[store.ScanOpts]{
		filter[store.ScanOpts]{key: "engine", label: "Engine", values: engineNames(api.KindScan)},
		filter[store.ScanOpts]{key: "profile", label: "Profile", values: r.vocabulary(store.ScanProfiles)},
		filter[store.ScanOpts]{key: "phase", label: "Phase", values: fixed(phaseNames()...)},
		filter[store.ScanOpts]{key: "severity", label: "Severity", values: fixed(severityNames()...)},
	}
}

func (r *Registry) findingFilters() []clicky.Filter[store.FindingOpts] {
	return []clicky.Filter[store.FindingOpts]{
		filter[store.FindingOpts]{key: "scan", label: "Scan", values: r.vocabulary(store.ScanNames)},
		filter[store.FindingOpts]{key: "severity", label: "Severity", values: fixed(severityNames()...)},
		filter[store.FindingOpts]{key: "host", label: "Host", values: r.vocabulary(store.FindingHosts)},
		filter[store.FindingOpts]{key: "template", label: "Template", values: r.vocabulary(store.FindingTemplates)},
		filter[store.FindingOpts]{key: "tag", label: "Tag", values: r.vocabulary(store.FindingTags)},
	}
}

func (r *Registry) profileFilters() []clicky.Filter[store.ProfileOpts] {
	return []clicky.Filter[store.ProfileOpts]{
		filter[store.ProfileOpts]{key: "kind", label: "Kind", values: fixed(api.Kinds()...)},
		filter[store.ProfileOpts]{key: "engine", label: "Engine", values: engineNames(api.Kinds()...)},
	}
}

// templateFilters narrow the engines' template catalogues.
//
// The vocabularies come from the installed templates rather than from a fixed
// list, so a tag that appears in a new templates release is offerable the moment
// it is installed — the catalogue is the source of truth, and nothing here
// duplicates it.
func (r *Registry) templateFilters() []clicky.Filter[TemplateOpts] {
	return []clicky.Filter[TemplateOpts]{
		filter[TemplateOpts]{key: "engine", label: "Engine", values: engineNames(api.KindScan)},
		filter[TemplateOpts]{key: "severity", label: "Severity", values: fixed(severityNames()...)},
		filter[TemplateOpts]{key: "type", label: "Protocol", values: r.templateValues(func(t api.Template) []string {
			return []string{t.Type}
		})},
		filter[TemplateOpts]{key: "tag", label: "Tag", values: r.templateValues(func(t api.Template) []string {
			return t.Tags
		})},
		filter[TemplateOpts]{key: "author", label: "Author", values: r.templateValues(func(t api.Template) []string {
			return t.Authors
		})},
		filter[TemplateOpts]{key: "profile", label: "Profile", values: r.vocabulary(store.ProfileNames)},
	}
}

// templateValues enumerates one field across every installed template.
func (r *Registry) templateValues(field func(api.Template) []string) values {
	return func(ctx context.Context) []string {
		templates, err := r.listTemplates(ctx, TemplateOpts{Limit: -1})
		if err != nil {
			logger.Debugf("template filter values: %v", err)
			return nil
		}

		seen := map[string]bool{}
		var found []string
		for _, template := range templates {
			for _, value := range field(template) {
				if value != "" && !seen[value] {
					seen[value] = true
					found = append(found, value)
				}
			}
		}
		sort.Strings(found)
		return found
	}
}

func discoverFilters() []clicky.Filter[store.DiscoverOpts] {
	return []clicky.Filter[store.DiscoverOpts]{
		filter[store.DiscoverOpts]{key: "chain", label: "Chain", values: fixed(discovery.ChainNames()...)},
	}
}

func engineFilters() []clicky.Filter[EngineOpts] {
	return []clicky.Filter[EngineOpts]{
		filter[EngineOpts]{key: "kind", label: "Kind", values: fixed(api.Kinds()...)},
	}
}

func classNames() []string {
	names := make([]string, 0, len(api.Classes()))
	for _, class := range api.Classes() {
		names = append(names, string(class))
	}
	return names
}

func severityNames() []string {
	names := make([]string, 0, len(api.Severities()))
	for _, severity := range api.Severities() {
		names = append(names, string(severity))
	}
	return names
}

func phaseNames() []string {
	names := make([]string, 0, len(api.Phases()))
	for _, phase := range api.Phases() {
		names = append(names, string(phase))
	}
	return names
}
