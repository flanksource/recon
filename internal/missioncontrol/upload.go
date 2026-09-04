package missioncontrol

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	dutymodels "github.com/flanksource/duty/models"
	"github.com/flanksource/duty/upstream"
	"github.com/flanksource/incident-commander/sdk"
	"github.com/google/uuid"

	"github.com/flanksource/recon/internal/api"
)

const DefaultAgent = "recon"

// ambiguityResourceSample bounds the resource names reported beside an
// ambiguous identity. An account rung is reached by every resource inside it,
// and a reader picking between two config items needs an example, not a census —
// InsightAmbiguity.States still carries the true count.
const ambiguityResourceSample = 10

type UnresolvedPolicy string

const (
	UnresolvedReport UnresolvedPolicy = "report"
	UnresolvedError  UnresolvedPolicy = "error"
)

// Progress reports how far a sync has got, so a caller can show a run that
// takes a catalog lookup per identity as something other than a silent pause.
type Progress struct {
	// Phase is PhaseResolve or PhasePush.
	Phase       string
	Done, Total int
	// Identity is what is being resolved right now, empty before the first state
	// and while pushing.
	Identity string
}

const (
	PhaseResolve = "resolve"
	PhasePush    = "push"
)

type SyncOptions struct {
	Agent      string
	DryRun     bool
	Unresolved UnresolvedPolicy
	// Choices attach an ambiguous identity to one of the config items offered
	// for it, keyed by identity.
	Choices map[string]uuid.UUID
	// Repin ignores the links previous syncs stored and resolves every
	// state against the catalog again.
	Repin bool
	// Progress is called as each state is resolved. Optional.
	Progress func(Progress)
}

// PinStore persists the config item a resource's insights were attached to.
type PinStore interface {
	ConfigPins(ctx context.Context, resourceIDs []string) (map[string]api.ConfigPin, error)
	SetConfigPins(ctx context.Context, pins map[string]api.ConfigPin) error
	ClearConfigPins(ctx context.Context, resourceIDs []string, server string) error
	ConfigLinkStates(ctx context.Context, resourceIDs []string) ([]api.InsightState, error)
}

type Uploader struct {
	Client   *sdk.Client
	Resolver *Resolver
	Pins     PinStore
	Server   string
	Context  string
}

// Plan is the preflight: every state resolved, nothing sent. A dry run is this
// and no more, which is what makes the preview and the sync agree.
type Plan struct {
	Result   api.InsightSync
	Analyses []dutymodels.ConfigAnalysis
	// Pins are the links this run used, persisted only after the insights land.
	Pins       map[string]api.ConfigPin
	ClearLinks []string
}

// Sync previews the given states and, unless this is a dry run or the policy
// refuses, pushes them. The preflight is returned either way: what a run would
// have done is the answer to the question a dry run asks and the explanation of
// a run that pushed less than expected.
func (u *Uploader) Sync(
	ctx context.Context,
	states []api.InsightState,
	targets map[string]api.TargetDocument,
	matchedResources int,
	options SyncOptions,
) (api.InsightSync, error) {
	plan, err := u.Plan(ctx, states, targets, matchedResources, options)
	if err != nil {
		return api.InsightSync{}, err
	}
	if err := plan.refusal(options.Unresolved); err != nil {
		return plan.Result, err
	}
	if options.DryRun {
		return plan.Result, nil
	}
	return u.Push(ctx, plan, options)
}

// refusal is the error a policy demands of this plan, or nil when it permits
// the push.
func (p *Plan) refusal(policy UnresolvedPolicy) error {
	if policy != UnresolvedError || len(p.Result.Unresolved) == 0 {
		return nil
	}
	return fmt.Errorf("%d of %d eligible states could not be resolved and unresolved=error was set; nothing was pushed",
		len(p.Result.Unresolved), p.Result.Eligible)
}

// Plan resolves every state against the catalog without sending anything.
func (u *Uploader) Plan(
	ctx context.Context,
	states []api.InsightState,
	targets map[string]api.TargetDocument,
	matchedResources int,
	options SyncOptions,
) (*Plan, error) {
	u.Server = normalizeServer(u.Server)
	agent := options.Agent
	if agent == "" {
		agent = DefaultAgent
	}
	u.Resolver.Choices = options.Choices
	pins, err := u.storedPins(ctx, states)
	if err != nil {
		return nil, err
	}
	configIDs := make([]string, 0, len(pins))
	seenConfig := map[string]bool{}
	for _, pin := range pins {
		if !seenConfig[pin.ConfigID] {
			seenConfig[pin.ConfigID] = true
			configIDs = append(configIDs, pin.ConfigID)
		}
	}
	sort.Strings(configIDs)
	if err := u.Resolver.preloadConfigItems(ctx, configIDs); err != nil {
		return nil, err
	}

	plan := &Plan{
		Result: api.InsightSync{
			Context: u.Context, Server: u.Server, Agent: agent, DryRun: options.DryRun,
			MatchedResources: matchedResources, MatchedStates: len(states),
		},
		Pins: map[string]api.ConfigPin{},
	}
	analyses := map[string]dutymodels.ConfigAnalysis{}
	configs := map[string]*api.InsightConfig{}
	ambiguities := newAmbiguities()
	clearLinks := map[string]bool{}
	unresolvedResources := map[string]bool{}

	for index, state := range states {
		report(options.Progress, Progress{
			Phase: PhaseResolve, Done: index, Total: len(states), Identity: state.Resource.Name,
		})
		if !eligibleState(state) {
			plan.Result.Skipped++
			continue
		}
		plan.Result.Eligible++

		previous := pins[state.Resource.ID]
		var reusable *api.ConfigPin
		if !options.Repin {
			reusable = previous
		}
		resolution, err := u.Resolver.Resolve(ctx, ResolveOptions{
			State: state, Target: targets[targetOf(state)], Pin: reusable,
		})
		if err != nil {
			return nil, err
		}
		ambiguities.record(state, resolution.Ambiguous)
		if resolution.Match == nil {
			plan.Result.Unresolved = append(plan.Result.Unresolved, *resolution.Unresolved)
			if state.Resource.ID != "" {
				if _, matched := plan.Pins[state.Resource.ID]; matched {
					return nil, conflictingResourceLink(state.Resource.ID)
				}
				unresolvedResources[state.Resource.ID] = true
			}
			if previous != nil && state.Resource.ID != "" {
				clearLinks[state.Resource.ID] = true
			}
			continue
		}

		match := *resolution.Match
		analysis, err := recordAnalysis(analyses, state, match.ConfigID)
		if err != nil {
			return nil, err
		}
		count(&plan.Result, analysis, match)
		if state.Resource.ID != "" {
			pin := api.ConfigPin{
				ConfigID: match.ConfigID.String(), Method: match.Method,
				RolledUp: match.RolledUp, Server: u.Server,
			}
			if unresolvedResources[state.Resource.ID] {
				return nil, conflictingResourceLink(state.Resource.ID)
			}
			if existing, found := plan.Pins[state.Resource.ID]; found && existing != pin {
				return nil, conflictingResourceLink(state.Resource.ID)
			}
			plan.Pins[state.Resource.ID] = pin
			delete(clearLinks, state.Resource.ID)
		}
		recordConfig(configs, match)
	}
	changed := linksChangedFrom(pins, plan.Pins, clearLinks)
	if len(changed) > 0 {
		closureStates, err := u.configLinkStates(ctx, states, sortedPinKeys(changed))
		if err != nil {
			return nil, err
		}
		for _, state := range closureStates {
			previous, found := changed[state.Resource.ID]
			if !found || !eligibleState(state) {
				continue
			}
			closed, err := u.closePrevious(ctx, analyses, state, previous)
			if err != nil {
				return nil, err
			}
			if closed {
				plan.Result.Closed++
			}
		}
	}

	plan.Result.Configs = sortedConfigs(configs)
	plan.Result.Ambiguous = ambiguities.report(options.Choices)
	plan.Analyses = sortedAnalyses(analyses)
	plan.ClearLinks = sortedKeys(clearLinks)
	report(options.Progress, Progress{Phase: PhaseResolve, Done: len(states), Total: len(states)})
	return plan, nil
}

// Push sends a plan's insights and then persists the links that produced them.
func (u *Uploader) Push(ctx context.Context, plan *Plan, options SyncOptions) (api.InsightSync, error) {
	if len(plan.Analyses) > 0 {
		report(options.Progress, Progress{Phase: PhasePush, Total: len(plan.Analyses)})
		if err := u.Client.PushUpstream(ctx, plan.Result.Agent, &upstream.PushData{
			ConfigAnalysis: plan.Analyses,
		}); err != nil {
			return plan.Result, fmt.Errorf("push %d insights to %s: %w", len(plan.Analyses), u.Server, err)
		}
		plan.Result.Pushed = len(plan.Analyses)
	}

	// Written only now: a link must never describe insights the destination did
	// not accept. Set before clearing disjoint stale links so a failed local write
	// cannot throw away a previously usable destination.
	if u.Pins != nil && len(plan.Pins) > 0 {
		if err := u.Pins.SetConfigPins(ctx, plan.Pins); err != nil {
			return plan.Result, fmt.Errorf("store %d config links: %w", len(plan.Pins), err)
		}
	}
	if u.Pins != nil && len(plan.ClearLinks) > 0 {
		if err := u.Pins.ClearConfigPins(ctx, plan.ClearLinks, u.Server); err != nil {
			return plan.Result, fmt.Errorf("clear %d stale config links: %w", len(plan.ClearLinks), err)
		}
	}
	if len(plan.Analyses) > 0 {
		report(options.Progress, Progress{Phase: PhasePush, Done: plan.Result.Pushed, Total: plan.Result.Pushed})
	}
	return plan.Result, nil
}

// storedPins reads links for the selected destination. Empty servers are legacy
// links from before destination scope was persisted and belong to the current
// configured server on their first upgraded sync.
func (u *Uploader) storedPins(
	ctx context.Context,
	states []api.InsightState,
) (map[string]*api.ConfigPin, error) {
	if u.Pins == nil {
		return nil, nil
	}
	ids := make([]string, 0, len(states))
	seen := map[string]bool{}
	for _, state := range states {
		if id := state.Resource.ID; id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	stored, err := u.Pins.ConfigPins(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("read the stored config links: %w", err)
	}
	pins := make(map[string]*api.ConfigPin, len(stored))
	for id, pin := range stored {
		pin.Server = normalizeServer(pin.Server)
		if pin.Server != "" && pin.Server != u.Server {
			continue
		}
		pins[id] = &pin
	}
	return pins, nil
}

func normalizeServer(server string) string {
	return strings.TrimRight(strings.TrimSpace(server), "/")
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedPinKeys(values map[string]api.ConfigPin) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func linksChangedFrom(
	previous map[string]*api.ConfigPin,
	current map[string]api.ConfigPin,
	cleared map[string]bool,
) map[string]api.ConfigPin {
	changed := map[string]api.ConfigPin{}
	for resourceID, old := range previous {
		link, matched := current[resourceID]
		if cleared[resourceID] || matched && link.ConfigID != old.ConfigID {
			changed[resourceID] = *old
		}
	}
	return changed
}

func (u *Uploader) configLinkStates(
	ctx context.Context,
	selected []api.InsightState,
	resourceIDs []string,
) ([]api.InsightState, error) {
	all, err := u.Pins.ConfigLinkStates(ctx, resourceIDs)
	if err != nil {
		return nil, fmt.Errorf("read states on %d changing config links: %w", len(resourceIDs), err)
	}
	byID := make(map[string]api.InsightState, len(all)+len(selected))
	for _, state := range all {
		byID[insightStateKey(state)] = state
	}
	for _, state := range selected {
		byID[insightStateKey(state)] = state
	}
	states := make([]api.InsightState, 0, len(byID))
	for _, state := range byID {
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool { return insightStateKey(states[i]) < insightStateKey(states[j]) })
	return states, nil
}

func insightStateKey(state api.InsightState) string {
	return strings.Join([]string{
		state.Resource.ID, state.State.Engine, state.State.CheckID,
	}, "\x00")
}

func eligibleState(state api.InsightState) bool {
	return state.Scan.Phase == api.PhaseDone &&
		(state.State.Status != api.StatusResolved || state.State.Occurrences != 0)
}

func conflictingResourceLink(resourceID string) error {
	return fmt.Errorf("resource %s resolves to different config destinations across its selected finding states", resourceID)
}

func (u *Uploader) closePrevious(
	ctx context.Context,
	analyses map[string]dutymodels.ConfigAnalysis,
	state api.InsightState,
	previous api.ConfigPin,
) (bool, error) {
	id, err := uuid.Parse(previous.ConfigID)
	if err != nil {
		return false, fmt.Errorf("stored config link %q for resource %s is not a uuid: %w",
			previous.ConfigID, state.Resource.ID, err)
	}
	item, err := u.Resolver.configItem(ctx, id)
	if err != nil {
		return false, err
	}
	if item == nil {
		return false, nil
	}
	reason := "config-link-changed"
	if item.DeletedAt != nil {
		reason = "config-deleted"
	}
	analysis, err := ClosedStateAnalysis(state, id, reason)
	if err != nil {
		return false, err
	}
	return recordPreparedAnalysis(analyses, state, analysis)
}

func report(progress func(Progress), at Progress) {
	if progress == nil {
		return
	}
	progress(at)
}

func targetOf(state api.InsightState) string {
	if state.State.TargetID != "" {
		return state.State.TargetID
	}
	return state.Resource.TargetID
}

func recordAnalysis(
	analyses map[string]dutymodels.ConfigAnalysis,
	state api.InsightState,
	config uuid.UUID,
) (dutymodels.ConfigAnalysis, error) {
	analysis, err := StateAnalysis(state, config)
	if err != nil {
		return dutymodels.ConfigAnalysis{}, err
	}
	_, err = recordPreparedAnalysis(analyses, state, analysis)
	return analysis, err
}

func recordPreparedAnalysis(
	analyses map[string]dutymodels.ConfigAnalysis,
	state api.InsightState,
	analysis dutymodels.ConfigAnalysis,
) (bool, error) {
	id := analysis.ID.String()
	if existing, found := analyses[id]; found && !reflect.DeepEqual(existing, analysis) {
		return false, fmt.Errorf("insight identity collision %s for %s/%s",
			id, state.State.Engine, state.State.CheckID)
	} else if found {
		return false, nil
	}
	analyses[id] = analysis
	return true, nil
}

func count(result *api.InsightSync, analysis dutymodels.ConfigAnalysis, match Match) {
	switch analysis.Status {
	case dutymodels.AnalysisStatusOpen:
		result.Open++
	case dutymodels.AnalysisStatusResolved:
		result.Resolved++
	case dutymodels.AnalysisStatusSilenced:
		result.Silenced++
	}
	if match.RolledUp {
		result.RolledUp++
	} else {
		result.Direct++
	}
	if match.Pinned {
		result.Pinned++
	}
}

func recordConfig(configs map[string]*api.InsightConfig, match Match) {
	id := match.ConfigID.String()
	if configs[id] == nil {
		configs[id] = &api.InsightConfig{
			ID: id, Name: match.ConfigName, Type: match.ConfigType, RolledUp: match.RolledUp,
		}
	}
	configs[id].Pinned = configs[id].Pinned || match.Pinned || match.Chosen
	configs[id].Insights++
}

func sortedConfigs(configs map[string]*api.InsightConfig) []api.InsightConfig {
	out := make([]api.InsightConfig, 0, len(configs))
	for _, config := range configs {
		out = append(out, *config)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Insights != out[j].Insights {
			return out[i].Insights > out[j].Insights
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedAnalyses(analyses map[string]dutymodels.ConfigAnalysis) []dutymodels.ConfigAnalysis {
	out := make([]dutymodels.ConfigAnalysis, 0, len(analyses))
	for _, analysis := range analyses {
		out = append(out, analysis)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID.String() < out[j].ID.String() })
	return out
}

func ParseUnresolvedPolicy(value string) (UnresolvedPolicy, error) {
	switch UnresolvedPolicy(strings.ToLower(strings.TrimSpace(value))) {
	case "", UnresolvedReport:
		return UnresolvedReport, nil
	case UnresolvedError:
		return UnresolvedError, nil
	default:
		return "", fmt.Errorf("unknown unresolved policy %q: expected %q or %q", value, UnresolvedReport, UnresolvedError)
	}
}
