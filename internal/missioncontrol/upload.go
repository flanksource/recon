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

	"github.com/flanksource/recon/internal/api"
)

const DefaultAgent = "recon"

type UnresolvedPolicy string

const (
	UnresolvedReport UnresolvedPolicy = "report"
	UnresolvedError  UnresolvedPolicy = "error"
)

type SyncOptions struct {
	Agent      string
	DryRun     bool
	Unresolved UnresolvedPolicy
}

type Uploader struct {
	Client   *sdk.Client
	Resolver *Resolver
	Server   string
	Context  string
}

func (u *Uploader) Sync(
	ctx context.Context,
	states []api.InsightState,
	targets map[string]api.TargetDocument,
	matchedResources int,
	options SyncOptions,
) (api.InsightSync, error) {
	agent := options.Agent
	if agent == "" {
		agent = DefaultAgent
	}
	result := api.InsightSync{
		Context: u.Context, Server: u.Server, Agent: agent, DryRun: options.DryRun,
		MatchedResources: matchedResources, MatchedStates: len(states),
	}
	u.Resolver.Agent = agent
	analyses := map[string]dutymodels.ConfigAnalysis{}
	configs := map[string]*api.InsightConfig{}
	notes := map[string]bool{}

	for _, state := range states {
		if state.Scan.Phase != api.PhaseDone || state.State.Status == api.StatusResolved && state.State.Occurrences == 0 {
			result.Skipped++
			continue
		}
		result.Eligible++
		targetID := state.State.TargetID
		if targetID == "" {
			targetID = state.Resource.TargetID
		}
		match, unresolved, err := u.Resolver.Resolve(ctx, ResolveOptions{State: state, Target: targets[targetID]})
		if err != nil {
			return result, err
		}
		if unresolved != nil {
			result.Unresolved = append(result.Unresolved, *unresolved)
			continue
		}
		analysis, err := StateAnalysis(state, match.ConfigID)
		if err != nil {
			return result, err
		}
		id := analysis.ID.String()
		if existing, found := analyses[id]; found && !reflect.DeepEqual(existing, analysis) {
			return result, fmt.Errorf("insight identity collision %s for %s/%s", id, state.State.Engine, state.State.CheckID)
		}
		analyses[id] = analysis
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
		if match.Note != "" {
			notes[match.Note] = true
		}
		configID := match.ConfigID.String()
		if configs[configID] == nil {
			configs[configID] = &api.InsightConfig{
				ID: configID, Name: match.ConfigName, Type: match.ConfigType, RolledUp: match.RolledUp,
			}
		}
		configs[configID].Insights++
	}
	result.Configs = sortedConfigs(configs)
	result.Notes = sortedKeys(notes)
	if options.Unresolved == UnresolvedError && len(result.Unresolved) > 0 {
		return result, fmt.Errorf("%d of %d eligible states could not be resolved and unresolved=error was set; nothing was pushed",
			len(result.Unresolved), result.Eligible)
	}
	if options.DryRun || len(analyses) == 0 {
		return result, nil
	}
	batch := make([]dutymodels.ConfigAnalysis, 0, len(analyses))
	for _, analysis := range analyses {
		batch = append(batch, analysis)
	}
	sort.Slice(batch, func(i, j int) bool { return batch[i].ID.String() < batch[j].ID.String() })
	if err := u.Client.PushUpstream(ctx, agent, &upstream.PushData{ConfigAnalysis: batch}); err != nil {
		return result, fmt.Errorf("push %d insights to %s: %w", len(batch), u.Server, err)
	}
	result.Pushed = len(batch)
	return result, nil
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

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
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
