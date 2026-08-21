package entities

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/flanksource/clicky"
	"github.com/flanksource/commons/collections"

	"github.com/flanksource/recon/internal/api"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/store"
)

// TemplateOpts selects templates from an engine's catalogue.
//
// Profile is the reason this entity exists: it answers "what would this profile
// run" with the templates themselves, from the same declaration that answers it
// as a count. Everything else narrows the catalogue directly.
type TemplateOpts struct {
	Engine   []string `json:"engine,omitempty" flag:"engine" help:"Only templates for these scan engines"`
	Severity []string `json:"severity,omitempty" flag:"severity" help:"Only templates of these severities"`
	Type     []string `json:"type,omitempty" flag:"type" help:"Only catalogue items in these service or protocol families; prefix ! to exclude"`
	Tag      []string `json:"tag,omitempty" flag:"tag" help:"Only templates carrying these tags; prefix ! to exclude"`
	Author   []string `json:"author,omitempty" flag:"author" help:"Only templates by these authors"`

	Profile string `json:"profile,omitempty" flag:"profile" help:"Only templates a stored profile would run, as kind:engine:name"`
	Search  string `json:"search,omitempty" flag:"search" help:"Match id, name or description"`
	Limit   int    `json:"limit,omitempty" flag:"limit" help:"Maximum templates to return"`
}

// templateLimit bounds an unbounded listing. The catalogue is over thirteen
// thousand templates, which is not a page.
const templateLimit = 500

func (r *Registry) registerTemplate() {
	clicky.NewEntity[api.Template, TemplateOpts, api.Template]("template").
		Aliases("templates").
		ToolGroup("scanning").
		ListWithContext(r.listTemplates).
		GetWithContext(r.getTemplate).
		Filters(r.templateFilters()...).
		Register()
}

// listTemplates reads the engines' catalogues rather than a table.
//
// Templates are installed alongside the engine, not stored here, so the
// catalogue on disk is the source of truth and there is nothing to keep in
// sync — the same reasoning as the engine entity.
func (r *Registry) listTemplates(ctx context.Context, opts TemplateOpts) ([]api.Template, error) {
	catalogues, err := catalogues(opts.Engine)
	if err != nil {
		return nil, err
	}

	var templates []api.Template
	for name, catalogue := range catalogues {
		selected, err := r.templatesFor(ctx, name, catalogue, opts)
		if err != nil {
			return nil, err
		}
		templates = append(templates, selected...)
	}

	templates = filterTemplates(templates, opts)
	sort.Slice(templates, func(i, j int) bool {
		if templates[i].Engine != templates[j].Engine {
			return templates[i].Engine < templates[j].Engine
		}
		return templates[i].Path < templates[j].Path
	})

	// A negative limit asks for the whole catalogue, which is what building a
	// filter's vocabulary needs: capping that at the default would derive the
	// offered tags and protocols from a 500-template sample and silently omit
	// every value past it. Zero is "unspecified" and takes the default.
	limit := opts.Limit
	if limit == 0 {
		limit = templateLimit
	}
	if limit > 0 && len(templates) > limit {
		templates = templates[:limit]
	}
	return templates, nil
}

// templatesFor narrows an engine's catalogue by profile, when one was named.
func (r *Registry) templatesFor(
	ctx context.Context,
	engine string,
	catalogue enginescan.Catalogue,
	opts TemplateOpts,
) ([]api.Template, error) {
	if opts.Profile == "" {
		return catalogue.Templates()
	}

	profile, err := r.profileConfig(ctx, engine, opts.Profile)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, nil
	}

	selector, ok := catalogue.(interface {
		Select(map[string]any) ([]api.Template, error)
	})
	if !ok {
		preview, err := catalogue.Preview(profile)
		if err != nil {
			return nil, err
		}
		return preview.Templates, nil
	}
	return selector.Select(profile)
}

// profileConfig resolves a profile reference, returning nil when it belongs to
// a different engine than the one being listed.
func (r *Registry) profileConfig(ctx context.Context, engine, reference string) (map[string]any, error) {
	st, err := r.store()
	if err != nil {
		return nil, err
	}

	id := reference
	if strings.Count(id, ":") != 2 {
		// A bare name is the common case from a UI that already knows the
		// engine, so it is completed rather than rejected.
		id = "scan:" + engine + ":" + reference
	}

	profile, err := st.GetProfile(ctx, id)
	if err != nil {
		return nil, err
	}
	if profile.Engine != engine {
		return nil, nil
	}
	return profile.Config, nil
}

func (r *Registry) getTemplate(ctx context.Context, id string) (api.Template, error) {
	templates, err := r.listTemplates(ctx, TemplateOpts{Limit: -1})
	if err != nil {
		return api.Template{}, err
	}
	for _, template := range templates {
		if template.ID == id {
			return template, nil
		}
	}
	return api.Template{}, store.NotFound("template", id)
}

// PreviewTemplates reports what a configuration would run, without storing it.
//
// It takes a configuration rather than a profile id because the question is
// asked while editing one: the profile form and the scan dialog both need an
// answer for a draft that has not been saved, and saving to find out what a
// change does is the loop this removes. Registry.Preview is the other half of
// the same question — which endpoints a scan would contact.
func (r *Registry) PreviewTemplates(engine string, config map[string]any) (api.TemplatePreview, error) {
	if engine == "" {
		engine = "nuclei"
	}
	found, err := enginescan.Get(engine)
	if err != nil {
		return api.TemplatePreview{}, err
	}
	catalogue, ok := found.(enginescan.Catalogue)
	if !ok {
		return api.TemplatePreview{}, fmt.Errorf(
			"%s cannot list the templates it would run", engine)
	}
	return catalogue.Preview(config)
}

// catalogues returns the engines that can describe their templates.
func catalogues(names []string) (map[string]enginescan.Catalogue, error) {
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}

	found := map[string]enginescan.Catalogue{}
	for _, engine := range enginescan.All() {
		name := engine.Spec().Name
		if len(wanted) > 0 && !wanted[name] {
			continue
		}
		if catalogue, ok := engine.(enginescan.Catalogue); ok {
			found[name] = catalogue
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no scan engine can list its templates")
	}
	return found, nil
}

func filterTemplates(templates []api.Template, opts TemplateOpts) []api.Template {
	kept := templates[:0]
	for _, template := range templates {
		switch {
		case !matchesAny(opts.Severity, template.Severity):
		case !collections.MatchItems(template.Type, opts.Type...):
		case !matchesTags(opts.Tag, template.Tags):
		case !matchesAnyOf(opts.Author, template.Authors):
		case !matchesSearch(opts.Search, template):
		default:
			kept = append(kept, template)
		}
	}
	return kept
}

// matchesTags applies the tag patterns to a template's whole tag set.
//
// A negated pattern excludes the template outright, which is why this cannot be
// "any tag matches": `--tag '!dos'` has to drop a template that is tagged both
// `network` and `dos`, not keep it because `network` was not excluded.
func matchesTags(patterns, tags []string) bool {
	if len(patterns) == 0 {
		return true
	}
	// An untagged template still has to survive an exclusion-only filter: it is
	// not tagged `dos`, so `--tag '!dos'` is not about it. Matching the empty
	// string gets that from the same rules rather than a second code path.
	if len(tags) == 0 {
		return collections.MatchItems("", patterns...)
	}
	matched, negated := collections.MatchAny(tags, patterns...)
	return matched && !negated
}

func matchesAny(wanted []string, value string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, want := range wanted {
		if strings.EqualFold(want, value) {
			return true
		}
	}
	return false
}

func matchesAnyOf(wanted, values []string) bool {
	if len(wanted) == 0 {
		return true
	}
	for _, want := range wanted {
		for _, value := range values {
			if strings.EqualFold(want, value) {
				return true
			}
		}
	}
	return false
}

func matchesSearch(search string, template api.Template) bool {
	if search == "" {
		return true
	}
	search = strings.ToLower(search)
	for _, field := range []string{template.ID, template.Name, template.Description, template.Path} {
		if strings.Contains(strings.ToLower(field), search) {
			return true
		}
	}
	return false
}
