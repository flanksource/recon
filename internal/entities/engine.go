package entities

import (
	"context"
	"sort"

	"github.com/flanksource/clicky"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/store"
)

// EngineOpts selects engines.
type EngineOpts struct {
	Kind      []string `json:"kind,omitempty" flag:"kind" help:"Only discovery or scan engines"`
	Installed bool     `json:"installed,omitempty" flag:"installed" help:"Only engines whose binary is resolvable"`
}

func (r *Registry) registerEngine() {
	clicky.NewEntity[api.EngineSpec, EngineOpts, api.EngineSpec]("engine").
		Aliases("engines").
		ToolGroup("configuration").
		ListWithContext(r.listEngines).
		GetWithContext(r.getEngine).
		Register()
}

// listEngines reads the two registries rather than a table. Engines are
// compiled in, so the registry is the source of truth and there is nothing to
// keep in sync.
func (r *Registry) listEngines(_ context.Context, opts EngineOpts) ([]api.EngineSpec, error) {
	wanted := map[string]bool{}
	for _, kind := range opts.Kind {
		wanted[kind] = true
	}
	keep := func(kind string) bool { return len(wanted) == 0 || wanted[kind] }

	var specs []api.EngineSpec
	if keep("discovery") {
		for _, engine := range discovery.All() {
			spec := r.describe(engine.Spec(), "discovery")
			spec.Accepts = string(engine.Accepts())
			spec.Emits = string(engine.Emits())
			specs = append(specs, spec)
		}
	}
	if keep("scan") {
		for _, engine := range scan.All() {
			specs = append(specs, r.describe(engine.Spec(), "scan"))
		}
	}

	if opts.Installed {
		var installed []api.EngineSpec
		for _, spec := range specs {
			if spec.Installed {
				installed = append(installed, spec)
			}
		}
		specs = installed
	}

	sort.Slice(specs, func(i, j int) bool {
		if specs[i].Kind != specs[j].Kind {
			return specs[i].Kind < specs[j].Kind
		}
		return specs[i].Name < specs[j].Name
	})
	return specs, nil
}

func (r *Registry) getEngine(ctx context.Context, name string) (api.EngineSpec, error) {
	found, err := r.listEngines(ctx, EngineOpts{})
	if err != nil {
		return api.EngineSpec{}, err
	}
	for _, spec := range found {
		if spec.Name == name {
			return spec, nil
		}
	}
	return api.EngineSpec{}, store.NotFound("engine", name)
}

// describe combines the compiled-in spec with what is installed here. The
// option catalog is included so the profile form has everything it needs from
// one request.
func (r *Registry) describe(spec engines.Spec, kind string) api.EngineSpec {
	described := api.EngineSpec{
		Name:        spec.Name,
		Kind:        kind,
		Title:       spec.Title,
		Description: spec.Description,
		DocsURL:     spec.DocsURL,
		Binary:      spec.Binary,
		Version:     spec.Version,
		Sections:    spec.Sections,
		Defaults:    spec.Defaults.Name,
	}

	if r.Provisioner != nil {
		status := r.Provisioner.Status(spec)
		described.Installed = status.Installed
		described.Managed = status.Managed
		described.Path = status.Path
		described.Problem = status.Problem
	}
	return described
}
