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
	// Repin ignores the choices previous syncs remembered and resolves every
	// state against the catalog again. It is the only way back out of a choice
	// that has since become wrong.
	Repin bool
	// Progress is called as each state is resolved. Optional.
	Progress func(Progress)
}

// PinStore remembers which config item a resource's insights were attached to.
// Reading it is what lets a later sync skip the ladder; writing it is what makes
// a choice stick.
type PinStore interface {
	ConfigPins(ctx context.Context, resourceIDs []string) (map[string]api.ConfigPin, error)
	SetConfigPins(ctx context.Context, pins map[string]api.ConfigPin) error
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
	// Pins are the choices this run made, to be remembered against the resources
	// they were made for once the insights actually land.
	Pins map[string]api.ConfigPin
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
	agent := options.Agent
	if agent == "" {
		agent = DefaultAgent
	}
	u.Resolver.Choices = options.Choices
	pins, err := u.storedPins(ctx, states, options)
	if err != nil {
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

	for index, state := range states {
		report(options.Progress, Progress{
			Phase: PhaseResolve, Done: index, Total: len(states), Identity: state.Resource.Name,
		})
		if state.Scan.Phase != api.PhaseDone || state.State.Status == api.StatusResolved && state.State.Occurrences == 0 {
			plan.Result.Skipped++
			continue
		}
		plan.Result.Eligible++

		resolution, err := u.Resolver.Resolve(ctx, ResolveOptions{
			State: state, Target: targets[targetOf(state)], Pin: pins[state.Resource.ID],
		})
		if err != nil {
			return nil, err
		}
		ambiguities.record(state, resolution.Ambiguous)
		if resolution.Match == nil {
			plan.Result.Unresolved = append(plan.Result.Unresolved, *resolution.Unresolved)
			continue
		}

		match := *resolution.Match
		analysis, err := recordAnalysis(analyses, state, match.ConfigID)
		if err != nil {
			return nil, err
		}
		count(&plan.Result, analysis, match)
		if match.Chosen {
			plan.Pins[state.Resource.ID] = api.ConfigPin{
				ConfigID: match.ConfigID.String(), RolledUp: match.RolledUp,
			}
		}
		recordConfig(configs, match)
	}

	plan.Result.Configs = sortedConfigs(configs)
	plan.Result.Ambiguous = ambiguities.report(options.Choices)
	plan.Analyses = sortedAnalyses(analyses)
	report(options.Progress, Progress{Phase: PhaseResolve, Done: len(states), Total: len(states)})
	return plan, nil
}

// Push sends a plan's insights and remembers the choices that produced them.
func (u *Uploader) Push(ctx context.Context, plan *Plan, options SyncOptions) (api.InsightSync, error) {
	if len(plan.Analyses) == 0 {
		return plan.Result, nil
	}
	report(options.Progress, Progress{Phase: PhasePush, Total: len(plan.Analyses)})
	if err := u.Client.PushUpstream(ctx, plan.Result.Agent, &upstream.PushData{
		ConfigAnalysis: plan.Analyses,
	}); err != nil {
		return plan.Result, fmt.Errorf("push %d insights to %s: %w", len(plan.Analyses), u.Server, err)
	}
	plan.Result.Pushed = len(plan.Analyses)

	// Written only now: a choice that describes insights nobody accepted would
	// be a preference recorded for a sync that never happened.
	if u.Pins != nil && len(plan.Pins) > 0 {
		if err := u.Pins.SetConfigPins(ctx, plan.Pins); err != nil {
			return plan.Result, fmt.Errorf("remember %d config choices: %w", len(plan.Pins), err)
		}
	}
	report(options.Progress, Progress{Phase: PhasePush, Done: plan.Result.Pushed, Total: plan.Result.Pushed})
	return plan.Result, nil
}

// storedPins reads the choices previous syncs remembered for these resources.
func (u *Uploader) storedPins(
	ctx context.Context,
	states []api.InsightState,
	options SyncOptions,
) (map[string]*api.ConfigPin, error) {
	if u.Pins == nil || options.Repin {
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
		return nil, fmt.Errorf("read the stored config choices: %w", err)
	}
	pins := make(map[string]*api.ConfigPin, len(stored))
	for id, pin := range stored {
		pins[id] = &pin
	}
	return pins, nil
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
	id := analysis.ID.String()
	if existing, found := analyses[id]; found && !reflect.DeepEqual(existing, analysis) {
		return dutymodels.ConfigAnalysis{}, fmt.Errorf("insight identity collision %s for %s/%s",
			id, state.State.Engine, state.State.CheckID)
	}
	analyses[id] = analysis
	return analysis, nil
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
