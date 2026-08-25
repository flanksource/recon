// Package entities declares every resource once.
//
// A clicky entity is simultaneously the CLI subcommand, the REST route, the
// OpenAPI operation and the UI's column and filter description. Declaring
// `target` here is what makes `reconctl target list --class non-prod` and
// `GET /api/v1/target?class=non-prod` the same operation rather than two
// implementations kept in agreement by hand.
package entities

import (
	"context"
	"fmt"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/entity"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/store"
)

// Registry holds what the entity handlers need.
//
// The store is resolved when a handler runs, not when it is registered: the
// command tree has to exist before flags are parsed, and the database cannot be
// opened until they are.
type Registry struct {
	Provisioner *engines.Provisioner

	// Runtimes drive the operations that do something rather than return
	// something. Optional: without them those commands are simply not offered.
	Runtimes Runtimes

	st *store.Store
}

// SetStore supplies the open database. Every handler fails loudly until it is
// called, rather than returning an empty result that reads like an empty
// inventory.
func (r *Registry) SetStore(st *store.Store) {
	if st != nil {
		st.SetProviderContextValidator(func(ctx context.Context, target api.TargetDocument) error {
			return validateProviderContext(ctx, st, target)
		})
	}
	r.st = st
}

func (r *Registry) store() (*store.Store, error) {
	if r.st == nil {
		return nil, fmt.Errorf("database is not open: this command needs a connection")
	}
	return r.st, nil
}

// Store exposes the open database to the hand-written commands, which reach the
// same tables as the generated ones but are not entity operations. It fails the
// same way rather than handing back a nil store.
func (r *Registry) Store() (*store.Store, error) { return r.store() }

// bind adapts a store method to an entity handler, resolving the store at call
// time. Used with a method expression — bind(r, (*store.Store).ListTargets) —
// so the handler and the store method cannot drift apart.
func bind[A, R any](r *Registry, fn func(*store.Store, context.Context, A) (R, error)) func(context.Context, A) (R, error) {
	return func(ctx context.Context, arg A) (R, error) {
		var zero R
		st, err := r.store()
		if err != nil {
			return zero, err
		}
		return fn(st, ctx, arg)
	}
}

// bind2 is bind for the two-argument handlers: update and delete.
func bind2[A, B, R any](r *Registry, fn func(*store.Store, context.Context, A, B) (R, error)) func(context.Context, A, B) (R, error) {
	return func(ctx context.Context, first A, second B) (R, error) {
		var zero R
		st, err := r.store()
		if err != nil {
			return zero, err
		}
		return fn(st, ctx, first, second)
	}
}

// Register declares every entity. Call once, before serving: the OpenAPI spec is
// built from the registry on first request and then cached, so an entity
// registered later would be missing from it.
func (r *Registry) Register() {
	r.registerTarget()
	r.registerScan()
	r.registerFinding()
	r.registerFindingGroup()
	r.registerFindingState()
	r.registerResource()
	r.registerDiscover()
	r.registerProbe()
	r.registerProfile()
	r.registerMute()
	r.registerTemplate()
	r.registerEngine()
	r.registerZone()
	r.registerConnection()
}

// registerZone exposes the zones discovery enumerates. They are configured, not
// discovered: with none set, a sweep has nothing to start from.
func (r *Registry) registerZone() {
	clicky.NewEntity[api.Zone, store.ZoneOpts, api.Zone]("zone").
		Aliases("zones").
		ToolGroup("configuration").
		ListWithContext(bind(r, (*store.Store).ListZoneDocuments)).
		GetWithContext(bind(r, (*store.Store).GetZone)).
		CreateWithContext(bind(r, addZone)).
		DeleteWithContext(deleteZone(r)).
		Register()
}

func addZone(st *store.Store, ctx context.Context, body map[string]any) (api.Zone, error) {
	name, _ := body["zone"].(string)
	if name == "" {
		name, _ = body["id"].(string)
	}
	return st.AddZone(ctx, name)
}

func deleteZone(r *Registry) func(context.Context, string) error {
	return func(ctx context.Context, id string) error {
		st, err := r.store()
		if err != nil {
			return err
		}
		return st.DeleteZone(ctx, id)
	}
}

func (r *Registry) registerTarget() {
	clicky.NewEntity[api.TargetDocument, store.TargetOpts, api.TargetDocument]("target").
		Aliases("targets").
		ToolGroup("inventory").
		ListWithContext(bind(r, (*store.Store).ListTargets)).
		GetWithContext(bind(r, (*store.Store).GetTarget)).
		CreateWithContext(bind(r, createTarget)).
		UpdateWithContext(bind2(r, updateTarget)).
		DeleteWithContext(deleteTarget(r)).
		Filters(r.targetFilters()...).
		Register()
}

// deleteTarget removes a target. Like deleteZone it has no result to return, so
// it does not fit bind.
func deleteTarget(r *Registry) func(context.Context, string) error {
	return func(ctx context.Context, host string) error {
		st, err := r.store()
		if err != nil {
			return err
		}
		return st.DeleteTarget(ctx, host)
	}
}

// createTarget adds a curated target directly. Discovery-created targets enter
// the same inventory as unclassified records and can be updated in place.
func createTarget(st *store.Store, ctx context.Context, body map[string]any) (api.TargetDocument, error) {
	var err error
	body, err = requestBody(ctx, body)
	if err != nil {
		return api.TargetDocument{}, err
	}
	target, err := api.TargetFrom(body)
	if err != nil {
		return api.TargetDocument{}, err
	}
	return st.CreateTarget(ctx, target)
}

// updateTarget applies an atomic edit to curated fields and mutable provider
// context configuration.
//
// The machine-owned sections are not editable through this path at all: they
// are discovery's output, and letting an edit overwrite them would mean a
// correction survives exactly until the next sweep.
func updateTarget(st *store.Store, ctx context.Context, id string, body map[string]any) (api.TargetDocument, error) {
	var err error
	body, err = requestBody(ctx, body)
	if err != nil {
		return api.TargetDocument{}, err
	}
	delete(body, "id")
	update, err := api.TargetUpdateFrom(body)
	if err != nil {
		return api.TargetDocument{}, err
	}
	return st.UpdateTarget(ctx, id, update)
}

func (r *Registry) registerScan() {
	builder := clicky.NewEntity[api.Scan, store.ScanOpts, api.Scan]("scan").
		Aliases("scans").
		ToolGroup("scanning").
		ListWithContext(bind(r, (*store.Store).ListScans)).
		GetWithContext(bind(r, (*store.Store).GetScan)).
		Filters(r.scanFilters()...)
	if r.Runtimes.Scans != nil && r.Runtimes.Discovery != nil {
		builder.WithPrimaryAction(entity.PrimaryActionWithContext(scanRunOpts{}, r.scanSelection).
			WithShort("Discover targets, then scan their endpoints"))
	}
	builder.Register()
}

func (r *Registry) registerFinding() {
	// Deliberately not Parent("scan"). Nesting generates both
	// /scan/{scan}/finding and /scan/finding/{id}, which net/http rejects as
	// ambiguous — neither pattern is more specific. The drill-down is
	// `finding list --scan <id>` instead, which is the same query and is also
	// how findings are compared across runs.
	clicky.NewEntity[api.Finding, store.FindingOpts, api.Finding]("finding").
		Aliases("findings").
		ToolGroup("scanning").
		ListPagedWithContext(pagedFindings(bind(r, (*store.Store).ListFindingsPaged))).
		GetWithContext(bind(r, (*store.Store).GetFinding)).
		Filters(r.findingFilters()...).
		WithAction(entity.TypedActionWithContext("sync", findingSyncFlags{}, r.syncFindings).
			WithOptionalID().WithShort("Sync the selected current finding states to Mission Control")).
		WithAction(entity.TypedActionWithContext("mute", findingMuteFlags{}, r.muteFinding).
			WithShort("Create a mute rule from this finding")).
		Register()
}

func (r *Registry) registerFindingGroup() {
	clicky.NewEntity[api.FindingGroup, store.FindingStateOpts, api.FindingGroup]("finding-group").
		Aliases("finding-groups").
		ToolGroup("scanning").
		ListPagedWithContext(pagedFindingGroups(bind(r, (*store.Store).ListFindingGroupsPaged))).
		Filters(r.findingStateFilters()...).
		Register()
}

func (r *Registry) registerFindingState() {
	clicky.NewEntity[api.FindingState, store.FindingStateOpts, api.FindingState]("finding-state").
		Aliases("finding-states").
		ToolGroup("scanning").
		ListPagedWithContext(pagedFindingStates(bind(r, (*store.Store).ListFindingStatesPaged))).
		Filters(r.findingStateFilters()...).
		Register()
}

func pagedFindingGroups(
	list func(context.Context, store.FindingStateOpts) (api.FindingGroupPage, error),
) func(context.Context, store.FindingStateOpts) (entity.PagedResult[api.FindingGroup], error) {
	return func(ctx context.Context, opts store.FindingStateOpts) (entity.PagedResult[api.FindingGroup], error) {
		if len(opts.Status) == 0 {
			opts.Status = []string{api.StatusOpen}
		}
		page, err := list(ctx, opts)
		if err != nil {
			return entity.PagedResult[api.FindingGroup]{}, err
		}
		return entity.NewPagedResult(page.Data, page.Page.Limit, page.Page.Offset, page.Page.Total), nil
	}
}

func pagedFindingStates(
	list func(context.Context, store.FindingStateOpts) (api.FindingStatePage, error),
) func(context.Context, store.FindingStateOpts) (entity.PagedResult[api.FindingState], error) {
	return func(ctx context.Context, opts store.FindingStateOpts) (entity.PagedResult[api.FindingState], error) {
		if len(opts.Status) == 0 {
			opts.Status = []string{api.StatusOpen}
		}
		page, err := list(ctx, opts)
		if err != nil {
			return entity.PagedResult[api.FindingState]{}, err
		}
		return entity.NewPagedResult(page.Data, page.Page.Limit, page.Page.Offset, page.Page.Total), nil
	}
}

func pagedFindings(
	list func(context.Context, store.FindingOpts) (api.FindingPage, error),
) func(context.Context, store.FindingOpts) (entity.PagedResult[api.Finding], error) {
	return func(ctx context.Context, opts store.FindingOpts) (entity.PagedResult[api.Finding], error) {
		page, err := list(ctx, opts)
		if err != nil {
			return entity.PagedResult[api.Finding]{}, err
		}
		return entity.NewPagedResult(page.Data, page.Page.Limit, page.Page.Offset, page.Page.Total), nil
	}
}

func (r *Registry) registerDiscover() {
	builder := clicky.NewEntity[api.Discover, store.DiscoverOpts, api.Discover]("discover").
		Aliases("discoveries").
		ToolGroup("inventory").
		ListWithContext(bind(r, (*store.Store).ListDiscoveries)).
		GetWithContext(bind(r, (*store.Store).GetDiscovery)).
		Filters(discoverFilters()...)
	if r.Runtimes.Discovery != nil {
		builder.WithPrimaryAction(entity.PrimaryActionWithContext(discoverRunOpts{}, r.discoverSelection).
			WithShort("Discover domains, networks, hosts or selected inventory targets"))
	}
	builder.Register()
}

// registerProbe exposes liveness sweeps.
//
// A probe used to be a bare command with no history: it folded what it saw into
// the targets and the run was the response. It is an entity now for the same
// reason a scan is one — "what did the last sweep find" has to outlive the
// request that ran it.
//
// Unlike `reconctl ping` this is served over HTTP, which is safe because a probe
// can only reach hosts already in the inventory; a free-form prober would be a
// way to reach anything the server can.
func (r *Registry) registerProbe() {
	builder := clicky.NewEntity[api.ProbeRun, store.ProbeOpts, api.ProbeRun]("probe").
		Aliases("probes").
		ToolGroup("inventory").
		ListWithContext(bind(r, (*store.Store).ListProbes)).
		GetWithContext(bind(r, (*store.Store).GetProbe)).
		Filters(r.probeFilters()...)
	if r.Runtimes.Probes != nil {
		builder.WithPrimaryAction(entity.PrimaryActionWithContext(probeRunOpts{}, r.ProbeTargets).
			WithShort("Probe inventory targets and refresh their liveness"))
	}
	builder.Register()
}

func (r *Registry) registerProfile() {
	clicky.NewEntity[api.Profile, store.ProfileOpts, api.Profile]("profile").
		Aliases("profiles").
		ToolGroup("configuration").
		ListWithContext(bind(r, listProfiles)).
		GetWithContext(bind(r, getProfile)).
		CreateWithContext(bind(r, saveProfile)).
		UpdateWithContext(bind2(r, updateProfile)).
		DeleteWithContext(deleteProfile(r)).
		Filters(r.profileFilters()...).
		Register()
}

// withRisk asks the scan engine what it makes of a stored configuration.
//
// The judgement lives in the engine, so this is the only way a caller can gate
// on the same rule the runtime enforces. Discovery profiles are never intrusive
// and an unregistered engine is left unannotated rather than assumed safe.
func withRisk(profile api.Profile) api.Profile {
	if profile.Kind != "scan" {
		return profile
	}
	engine, err := enginescan.Get(profile.Engine)
	if err != nil {
		return profile
	}

	risk := engine.Risk(profile.Config)
	profile.Intrusive, profile.Reason = risk.Intrusive, risk.Reason
	return profile
}

func listProfiles(st *store.Store, ctx context.Context, opts store.ProfileOpts) ([]api.Profile, error) {
	profiles, err := st.ListProfiles(ctx, opts)
	for i := range profiles {
		profiles[i] = withRisk(profiles[i])
	}
	return profiles, err
}

func getProfile(st *store.Store, ctx context.Context, id string) (api.Profile, error) {
	profile, err := st.GetProfile(ctx, id)
	if err != nil {
		return profile, err
	}
	return withRisk(profile), nil
}

func saveProfile(st *store.Store, ctx context.Context, body map[string]any) (api.Profile, error) {
	profile, err := api.ProfileFrom(body)
	if err != nil {
		return api.Profile{}, err
	}
	return st.SaveProfile(ctx, profile)
}

// updateProfile edits an existing profile. The address comes from the path, not
// the body, so an edit cannot silently rename or re-target a profile.
func updateProfile(st *store.Store, ctx context.Context, id string, body map[string]any) (api.Profile, error) {
	existing, err := st.GetProfile(ctx, id)
	if err != nil {
		return api.Profile{}, err
	}

	updated, err := api.ProfileFrom(body)
	if err != nil {
		return api.Profile{}, err
	}
	updated.Kind, updated.Engine, updated.Name = existing.Kind, existing.Engine, existing.Name
	return st.SaveProfile(ctx, updated)
}

// deleteProfile has no result to return, so it does not fit bind.
func deleteProfile(r *Registry) func(context.Context, string) error {
	return func(ctx context.Context, id string) error {
		st, err := r.store()
		if err != nil {
			return err
		}
		return st.DeleteProfile(ctx, id)
	}
}
