package missioncontrol

import (
	"context"
	"sort"
	"strings"

	dutymodels "github.com/flanksource/duty/models"
	"github.com/google/uuid"

	"github.com/flanksource/recon/internal/api"
)

// ambiguities collects one report per identity across every state that reached
// it. The resolver memoises its lookups, so the same ambiguity is handed back
// for every state in an account — the count of those states is exactly what
// says how much is riding on the choice.
type ambiguities struct {
	order    []string
	byID     map[string]*api.InsightAmbiguity
	resource map[string]map[string]bool
}

func newAmbiguities() *ambiguities {
	return &ambiguities{byID: map[string]*api.InsightAmbiguity{}, resource: map[string]map[string]bool{}}
}

func (a *ambiguities) record(state api.InsightState, found []Ambiguity) {
	for _, ambiguity := range found {
		report, seen := a.byID[ambiguity.Identity]
		if !seen {
			report = &api.InsightAmbiguity{
				Identity: ambiguity.Identity, Type: ambiguity.Type,
				Scope: ambiguity.Scope, Options: ambiguity.Options,
			}
			a.byID[ambiguity.Identity] = report
			a.resource[ambiguity.Identity] = map[string]bool{}
			a.order = append(a.order, ambiguity.Identity)
		}
		report.States++
		name := state.Resource.Name
		if name == "" {
			name = state.Resource.UID
		}
		if names := a.resource[ambiguity.Identity]; !names[name] {
			names[name] = true
			if len(report.Resources) < ambiguityResourceSample {
				report.Resources = append(report.Resources, name)
			}
		}
	}
}

func (a *ambiguities) report(choices map[string]uuid.UUID) []api.InsightAmbiguity {
	out := make([]api.InsightAmbiguity, 0, len(a.order))
	for _, identity := range a.order {
		ambiguity := *a.byID[identity]
		if chosen, found := choices[identity]; found {
			ambiguity.Chosen = chosen.String()
		}
		out = append(out, ambiguity)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].States != out[j].States {
			return out[i].States > out[j].States
		}
		return out[i].Identity < out[j].Identity
	})
	return out
}

// choices turns the config items that all carried one identity into the options
// a person can pick between.
//
// The items that carried it come first, and what contains them is offered
// alongside: a name duplicated across two scrapes of the same estate is
// frequently best answered by the project or cluster holding both, and that item
// never carried the identity itself so it is not in the match set. Nothing here
// picks — resolving by rule is what put an insight on the wrong resource in the
// first place, and a wrong attachment is worse than one that is still missing.
func (r *Resolver) choices(ctx context.Context, exact []dutymodels.ConfigItem) ([]api.InsightChoice, error) {
	options := make([]api.InsightChoice, 0, 2*len(exact))
	seen := map[uuid.UUID]bool{}
	for _, item := range exact {
		options = append(options, choiceOf(item, false))
		seen[item.ID] = true
	}
	ancestors := make([]api.InsightChoice, 0, len(exact))
	for _, item := range exact {
		ancestor := ancestorOf(item)
		if ancestor == uuid.Nil || seen[ancestor] {
			continue
		}
		seen[ancestor] = true
		found, err := r.configItem(ctx, ancestor)
		if err != nil {
			return nil, err
		}
		if found == nil {
			continue
		}
		ancestors = append(ancestors, choiceOf(*found, true))
	}
	sortChoices(options)
	sortChoices(ancestors)
	return append(options, ancestors...), nil
}

// matched counts the options that carried the identity themselves, which is
// what makes an identity ambiguous — the containing items are offered as a way
// out of the ambiguity, not as part of it.
func matched(options []api.InsightChoice) int {
	count := 0
	for _, option := range options {
		if !option.Ancestor {
			count++
		}
	}
	return count
}

func choiceOf(item dutymodels.ConfigItem, ancestor bool) api.InsightChoice {
	return api.InsightChoice{
		ID:       item.ID.String(),
		Name:     derefString(item.Name),
		Type:     derefString(item.Type),
		Root:     ancestorOf(item) == uuid.Nil,
		Ancestor: ancestor,
		Deleted:  item.DeletedAt != nil,
	}
}

// ancestorOf is the outermost config item containing this one: the first
// foreign segment of the materialised path, which is a dot-separated chain of
// ids from the root down. The immediate parent is the fallback for a server
// that sent no path — coarser than the root, but still a real container.
func ancestorOf(item dutymodels.ConfigItem) uuid.UUID {
	for _, segment := range strings.Split(item.Path, ".") {
		id, err := uuid.Parse(segment)
		if err != nil || id == item.ID {
			continue
		}
		return id
	}
	if item.ParentID != nil {
		return *item.ParentID
	}
	return uuid.Nil
}

// sortChoices orders by name so the same catalog always offers the same list;
// the id breaks the tie that duplicate names guarantee here.
func sortChoices(choices []api.InsightChoice) {
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].Name != choices[j].Name {
			return choices[i].Name < choices[j].Name
		}
		return choices[i].ID < choices[j].ID
	})
}
