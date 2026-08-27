package entities

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/missioncontrol"
	"github.com/flanksource/recon/internal/store"
)

type syncFlags struct {
	Context    string   `flag:"context" help:"Mission Control context; defaults to the current faro context"`
	Agent      string   `flag:"agent" help:"Agent name the insights are attributed to" default:"recon"`
	Unresolved string   `flag:"unresolved" help:"What to do with unresolved resources: report or error" default:"report"`
	Config     []string `flag:"config" help:"Attach an identity that matched several config items to one of them, as identity=config-id"`
	Repin      bool     `flag:"repin" help:"Ignore remembered config choices and resolve every state against the catalog again"`
	DryRun     bool     `flag:"dry-run" help:"Resolve and preview without writing"`
}

type resourceSyncFlags struct {
	store.ResourceOpts
	syncFlags
}

type findingSyncFlags struct {
	store.FindingStateOpts
	syncFlags
}

func (resourceSyncFlags) ClickyActionFlags() {}
func (findingSyncFlags) ClickyActionFlags()  {}

// choices reads the `identity=config-id` pairs. A malformed pair is an error
// rather than a skipped choice: the sync it was meant to steer would otherwise
// attach the same findings somewhere else and report success.
func (f syncFlags) choices() (map[string]uuid.UUID, error) {
	if len(f.Config) == 0 {
		return nil, nil
	}
	choices := make(map[string]uuid.UUID, len(f.Config))
	for _, pair := range f.Config {
		identity, id, split := strings.Cut(pair, "=")
		identity = strings.TrimSpace(identity)
		if !split || identity == "" {
			return nil, fmt.Errorf("--config %q is not identity=config-id", pair)
		}
		parsed, err := uuid.Parse(strings.TrimSpace(id))
		if err != nil {
			return nil, fmt.Errorf("--config %q: %q is not a config item id", pair, strings.TrimSpace(id))
		}
		choices[identity] = parsed
	}
	return choices, nil
}

func (r *Registry) syncResources(ctx context.Context, _ string, opts resourceSyncFlags) (api.InsightSync, error) {
	st, err := r.store()
	if err != nil {
		return api.InsightSync{}, err
	}
	selector := opts.ResourceOpts
	selector.Limit, selector.Offset = 0, 0
	resources, err := st.ListResources(ctx, selector)
	if err != nil {
		return api.InsightSync{}, err
	}
	if len(resources) == 0 {
		return r.pushStates(ctx, st, nil, 0, opts.syncFlags)
	}
	stateOpts := store.FindingStateOpts{Resource: make([]string, 0, len(resources))}
	for _, resource := range resources {
		stateOpts.Resource = append(stateOpts.Resource, resource.ID)
	}
	return r.syncStates(ctx, st, stateOpts, len(resources), opts.syncFlags)
}

func (r *Registry) syncFindings(ctx context.Context, _ string, opts findingSyncFlags) (api.InsightSync, error) {
	st, err := r.store()
	if err != nil {
		return api.InsightSync{}, err
	}
	selector := opts.FindingStateOpts
	selector.Limit, selector.Offset = 0, 0
	if len(selector.Status) == 0 {
		selector.Status = []string{api.StatusOpen}
	}
	states, err := st.ListInsightStates(ctx, selector)
	if err != nil {
		return api.InsightSync{}, err
	}
	resources := map[string]struct{}{}
	for _, state := range states {
		resources[state.Resource.ID] = struct{}{}
	}
	return r.pushStates(ctx, st, states, len(resources), opts.syncFlags)
}

func (r *Registry) syncStates(
	ctx context.Context,
	st *store.Store,
	selector store.FindingStateOpts,
	matchedResources int,
	flags syncFlags,
) (api.InsightSync, error) {
	states, err := st.ListInsightStates(ctx, selector)
	if err != nil {
		return api.InsightSync{}, err
	}
	return r.pushStates(ctx, st, states, matchedResources, flags)
}

func (r *Registry) pushStates(
	ctx context.Context,
	st *store.Store,
	states []api.InsightState,
	matchedResources int,
	flags syncFlags,
) (api.InsightSync, error) {
	unresolved, err := missioncontrol.ParseUnresolvedPolicy(flags.Unresolved)
	if err != nil {
		return api.InsightSync{}, err
	}
	choices, err := flags.choices()
	if err != nil {
		return api.InsightSync{}, err
	}
	targets, err := stateTargets(ctx, st, states)
	if err != nil {
		return api.InsightSync{}, err
	}
	uploader, err := missioncontrol.NewUploader(flags.Context)
	if err != nil {
		return api.InsightSync{}, err
	}
	uploader.Pins = st

	result, err := runSync(ctx, uploader, syncRequest{
		States:           states,
		Targets:          targets,
		MatchedResources: matchedResources,
		Options: missioncontrol.SyncOptions{
			Agent: flags.Agent, DryRun: flags.DryRun, Unresolved: unresolved,
			Choices: choices, Repin: flags.Repin,
		},
	})
	if err != nil {
		return result, fmt.Errorf("sync current insights: %w", err)
	}
	return result, nil
}

func stateTargets(ctx context.Context, st *store.Store, states []api.InsightState) (map[string]api.TargetDocument, error) {
	wanted := map[string]struct{}{}
	for _, state := range states {
		for _, id := range []string{state.State.TargetID, state.Resource.TargetID} {
			if id != "" {
				wanted[id] = struct{}{}
			}
		}
	}
	targets := make(map[string]api.TargetDocument, len(wanted))
	for id := range wanted {
		target, err := st.GetTarget(ctx, id)
		if err != nil {
			continue
		}
		targets[id] = target
	}
	return targets, nil
}
