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
func (r *Registry) SetStore(st *store.Store) { r.st = st }

func (r *Registry) store() (*store.Store, error) {
	if r.st == nil {
		return nil, fmt.Errorf("database is not open: this command needs a connection")
	}
	return r.st, nil
}

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
	r.registerDiscover()
	r.registerProfile()
	r.registerEngine()
	r.registerZone()
	r.registerActions()
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
		Filters(r.targetFilters()...).
		Register()
}

// createTarget classifies a host into the inventory.
//
// Discovery finds hosts but never classifies them, so this is the operation
// that turns one it found into a target. Without it the Discover dialog's "add
// to inventory" had nothing to call: an update refuses a host that is not
// already there, which is correct and left adding it impossible.
func createTarget(st *store.Store, ctx context.Context, body map[string]any) (api.TargetDocument, error) {
	host, curated, err := api.TargetFrom(body)
	if err != nil {
		return api.TargetDocument{}, err
	}
	return st.CreateTarget(ctx, host, curated)
}

// updateTarget applies an edit to the curated fields only.
//
// The machine-owned sections are not editable through this path at all: they
// are discovery's output, and letting an edit overwrite them would mean a
// correction survives exactly until the next sweep.
func updateTarget(st *store.Store, ctx context.Context, host string, body map[string]any) (api.TargetDocument, error) {
	curated, err := api.CuratedFrom(body)
	if err != nil {
		return api.TargetDocument{}, err
	}
	return st.UpdateCurated(ctx, host, curated)
}

func (r *Registry) registerScan() {
	clicky.NewEntity[api.Scan, store.ScanOpts, api.Scan]("scan").
		Aliases("scans").
		ToolGroup("scanning").
		ListWithContext(bind(r, (*store.Store).ListScans)).
		GetWithContext(bind(r, (*store.Store).GetScan)).
		Filters(r.scanFilters()...).
		Register()
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
		ListWithContext(bind(r, (*store.Store).ListFindings)).
		GetWithContext(bind(r, getFinding)).
		Filters(r.findingFilters()...).
		Register()
}

// getFinding resolves a finding by its scan#line address.
func getFinding(st *store.Store, ctx context.Context, id string) (api.Finding, error) {
	scan, line, err := api.SplitFindingID(id)
	if err != nil {
		return api.Finding{}, err
	}

	found, err := st.ListFindings(ctx, store.FindingOpts{Scan: []string{scan}})
	if err != nil {
		return api.Finding{}, err
	}
	for _, finding := range found {
		if finding.LineNo == line {
			return finding, nil
		}
	}
	return api.Finding{}, store.NotFound("finding", id)
}

func (r *Registry) registerDiscover() {
	clicky.NewEntity[api.Discover, store.DiscoverOpts, api.Discover]("discover").
		Aliases("discoveries").
		ToolGroup("inventory").
		ListWithContext(bind(r, (*store.Store).ListDiscoveries)).
		GetWithContext(bind(r, (*store.Store).GetDiscovery)).
		Filters(discoverFilters()...).
		Register()
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
