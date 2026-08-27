package missioncontrol

import (
	"context"
	"fmt"
	"strings"

	dutymodels "github.com/flanksource/duty/models"
	"github.com/flanksource/duty/query"
	dutytypes "github.com/flanksource/duty/types"
	"github.com/flanksource/incident-commander/sdk"
	"github.com/google/uuid"

	"github.com/flanksource/recon/internal/api"
)

// An insight has to hang off a config item Mission Control already knows about
// — config_analysis.config_id is a foreign key, and recon inventing its own
// config items would put a second, thinner copy of every host beside the real
// one. So each current state is resolved against the catalog instead.
//
// The ladder runs from the most specific identity the engine reported to the
// broadest scope the inventory records. Prowler names the resource it failed on
// and the account that owns it; nuclei names the scanned endpoint. When neither
// is in the catalog the state can still belong somewhere — the cluster or
// account the target sits in — which is what rolling up means. Only when even
// that is unknown is the finding reported unresolved rather than pushed to a
// guess.
type Candidate struct {
	Value string
	Type  string
	// Scope marks a rung that identifies the account, project or cluster rather
	// than the thing the finding is about.
	Scope bool
}

type ResolveOptions struct {
	State  api.InsightState
	Target api.TargetDocument
	// Pin is the choice a previous sync remembered for this state's resource. It
	// short-circuits the ladder: a person has already said where these findings
	// belong, and re-deriving it would let a catalog change quietly move them.
	Pin *api.ConfigPin
}

// Match is the config item a finding was attached to.
type Match struct {
	ConfigID   uuid.UUID
	ConfigName string
	ConfigType string
	// MatchedOn is the identity that resolved, which is not always the finding's
	// own — see RolledUp.
	MatchedOn string
	RolledUp  bool
	// Pinned marks a match that came from the resource's stored choice.
	Pinned bool
	// Chosen marks a match an explicit choice resolved this run, which is what a
	// real sync then remembers against the resource.
	Chosen bool
}

// Resolution is everything one state's walk down the ladder established: where
// it belongs, or why nothing could be found for it, and every identity that was
// too popular to decide on its own.
type Resolution struct {
	Match      *Match
	Unresolved *api.InsightUnresolved
	Ambiguous  []Ambiguity
}

// Ambiguity is one identity several config items carried, with everything a
// person needs to pick between them.
type Ambiguity struct {
	Identity string
	Type     string
	Scope    bool
	Options  []api.InsightChoice
}

// resolveLimit bounds a candidate lookup. One match is the answer and two are
// already ambiguous, so a page beyond a handful buys nothing.
const resolveLimit = 10

type lookup struct {
	match *Match
	// options is what an identity could be attached to, and is only populated
	// when more than one config item carried it.
	options []api.InsightChoice
}

// Resolver maps recon identities onto catalog config items. Lookups are
// memoised for the life of an upload: a scan of one host produces many findings
// that all resolve to the same config item.
//
// The search is deliberately not scoped to an agent. The agent an insight is
// pushed as is recon's own identity, and recon scrapes no config items — the
// config item a finding hangs off was ingested by whichever scraper or agent
// owns that estate. Scoping the search by the push agent would match nothing,
// and Mission Control rejects the whole query with `invalid agent` until the
// name exists upstream.
type Resolver struct {
	client *sdk.Client

	// Choices attach an ambiguous identity to one of the config items offered
	// for it. Keyed by the identity, because one account or cluster is the
	// answer for every resource inside it.
	Choices map[string]uuid.UUID

	cache map[string]lookup
	items map[uuid.UUID]*dutymodels.ConfigItem
}

func NewResolver(client *sdk.Client) *Resolver {
	return &Resolver{
		client: client,
		cache:  map[string]lookup{},
		items:  map[uuid.UUID]*dutymodels.ConfigItem{},
	}
}

// Resolve returns the config item a finding belongs to, or the report of why
// nothing could be found for it.
func (r *Resolver) Resolve(ctx context.Context, options ResolveOptions) (Resolution, error) {
	if options.Pin != nil {
		return r.resolvePin(ctx, options)
	}

	var resolution Resolution
	var tried []string

	for _, candidate := range candidates(options.State, options.Target) {
		tried = append(tried, candidate.Value)

		found, err := r.lookupCandidate(ctx, candidate)
		if err != nil {
			return Resolution{}, err
		}
		if len(found.options) > 0 {
			resolution.Ambiguous = append(resolution.Ambiguous, Ambiguity{
				Identity: candidate.Value, Type: candidate.Type, Scope: candidate.Scope,
				Options: found.options,
			})
			chosen := r.chosen(candidate.Value, found.options)
			if chosen == nil {
				continue
			}
			chosen.MatchedOn = candidate.Value
			chosen.RolledUp = candidate.Scope || chosen.RolledUp
			resolution.Match = chosen
			return resolution, nil
		}
		if found.match == nil {
			continue
		}

		match := *found.match
		match.MatchedOn = candidate.Value
		match.RolledUp = candidate.Scope
		resolution.Match = &match
		return resolution, nil
	}

	resolution.Unresolved = unresolved(options.State, tried, unresolvedReason(tried, resolution.Ambiguous))
	return resolution, nil
}

// resolvePin attaches a state to the config item chosen for its resource.
//
// The item is still read back rather than trusted: a config item that has been
// deleted since the choice was made would otherwise be pushed against, and
// config_analysis.config_id is a foreign key, so the whole batch would be
// rejected for one stale pin.
func (r *Resolver) resolvePin(ctx context.Context, options ResolveOptions) (Resolution, error) {
	id, err := uuid.Parse(options.Pin.ConfigID)
	if err != nil {
		return Resolution{}, fmt.Errorf("stored config choice %q for resource %s is not a uuid: %w",
			options.Pin.ConfigID, options.State.Resource.ID, err)
	}
	item, err := r.configItem(ctx, id)
	if err != nil {
		return Resolution{}, err
	}
	if item == nil {
		return Resolution{Unresolved: unresolved(options.State, []string{options.Pin.ConfigID},
			fmt.Sprintf("the chosen config item %s is no longer in the catalog; sync with --repin to resolve it again",
				options.Pin.ConfigID))}, nil
	}
	return Resolution{Match: &Match{
		ConfigID:   item.ID,
		ConfigName: derefString(item.Name),
		ConfigType: derefString(item.Type),
		MatchedOn:  derefString(item.Name),
		RolledUp:   options.Pin.RolledUp,
		Pinned:     true,
	}}, nil
}

// chosen returns the match an explicit choice made for this identity, or nil
// when nobody has chosen or the choice names something that was not offered.
func (r *Resolver) chosen(identity string, options []api.InsightChoice) *Match {
	id, found := r.Choices[identity]
	if !found {
		return nil
	}
	for _, option := range options {
		if option.ID != id.String() {
			continue
		}
		return &Match{
			ConfigID: id, ConfigName: option.Name, ConfigType: option.Type,
			// An ancestor is by definition not the thing the finding is about.
			RolledUp: option.Ancestor,
			Chosen:   true,
		}
	}
	return nil
}

func unresolvedReason(tried []string, ambiguous []Ambiguity) string {
	if len(tried) == 0 {
		return "the finding carries no identity to resolve against"
	}
	if len(ambiguous) == 0 {
		return "no catalog config item matches the resource, its account, cluster or target"
	}
	reasons := make([]string, 0, len(ambiguous))
	for _, ambiguity := range ambiguous {
		reasons = append(reasons, fmt.Sprintf("%s matched %d config items; choose one",
			ambiguity.Identity, matched(ambiguity.Options)))
	}
	return strings.Join(reasons, "; ")
}

func unresolved(state api.InsightState, tried []string, reason string) *api.InsightUnresolved {
	return &api.InsightUnresolved{
		Finding:  findingRef(state.Scan, state.Finding),
		Host:     state.Resource.Name,
		Severity: state.Finding.SeverityLevel(),
		Tried:    tried,
		Reason:   reason,
	}
}

// candidates builds the ladder, most specific first, dropping duplicates and
// anything the search grammar cannot express verbatim.
func candidates(state api.InsightState, target api.TargetDocument) []Candidate {
	ladder := make([]Candidate, 0, len(state.Resource.ExternalIDs)+4)
	for _, externalID := range state.Resource.ExternalIDs {
		ladder = append(ladder, Candidate{Value: externalID, Type: state.Resource.ConfigType})
	}
	if state.Parent != nil {
		for _, externalID := range state.Parent.ExternalIDs {
			ladder = append(ladder, Candidate{Value: externalID, Type: state.Parent.ConfigType, Scope: true})
		}
	}
	ladder = append(ladder,
		Candidate{Value: target.Cluster, Scope: true},
		Candidate{Value: target.ID, Scope: true},
	)

	seen := map[string]bool{}
	out := make([]Candidate, 0, len(ladder))
	for _, candidate := range ladder {
		candidate.Value = strings.TrimSpace(candidate.Value)
		key := candidate.Type + "\x00" + candidate.Value
		if candidate.Value == "" || seen[key] || !searchable(candidate.Value) || !searchable(candidate.Type) {
			continue
		}
		seen[key] = true
		out = append(out, candidate)
	}
	return out
}

// searchable reports whether a value survives the search grammar unchanged. A
// quote ends the string literal, a comma splits it into two alternatives, and a
// star turns an exact comparison into a wildcard — each would silently widen
// the query into matching something else, so such a candidate is skipped rather
// than mangled. The next rung down still gets its turn.
func searchable(value string) bool {
	return !strings.ContainsAny(value, `",*`)
}

// lookupCandidate finds the config item for one identity.
//
// The query asks the server for an exact name or a substring of external_id.
// The substring is deliberate: external_id is a text[], and the search grammar
// compares it by casting the whole array to text, so an exact comparison can
// never match an array. Narrowing with LIKE and then confirming the exact value
// against the fetched rows is what keeps the match honest.
func (r *Resolver) lookupCandidate(ctx context.Context, candidate Candidate) (lookup, error) {
	cacheKey := candidate.Type + "\x00" + candidate.Value
	if cached, ok := r.cache[cacheKey]; ok {
		return cached, nil
	}
	search := fmt.Sprintf(`name="%s" | external_id="*%s*"`, candidate.Value, candidate.Value)
	if candidate.Type != "" {
		search = fmt.Sprintf(`type="%s" name="%s" | type="%s" external_id="*%s*"`,
			candidate.Type, candidate.Value, candidate.Type, candidate.Value)
	}

	resp, err := r.client.SearchCatalog(ctx, query.SearchResourcesRequest{
		Limit: resolveLimit,
		Configs: []dutytypes.ResourceSelector{{
			Search: search,
		}},
	})
	if err != nil {
		return lookup{}, fmt.Errorf("search the catalog for %q: %w", candidate.Value, err)
	}

	ids := make([]string, 0, len(resp.Configs))
	for _, config := range resp.Configs {
		ids = append(ids, config.ID)
	}
	items, err := r.client.GetCatalogItems(ctx, ids)
	if err != nil {
		return lookup{}, fmt.Errorf("read the catalog items matching %q: %w", candidate.Value, err)
	}

	var exact []dutymodels.ConfigItem
	for _, item := range items {
		r.items[item.ID] = &item
		if identifies(item, candidate) {
			exact = append(exact, item)
		}
	}

	result := lookup{}
	switch len(exact) {
	case 0:
	case 1:
		result.match = &Match{
			ConfigID:   exact[0].ID,
			ConfigName: derefString(exact[0].Name),
			ConfigType: derefString(exact[0].Type),
		}
	default:
		result.options, err = r.choices(ctx, exact)
		if err != nil {
			return lookup{}, err
		}
	}
	r.cache[cacheKey] = result
	return result, nil
}

// configItem reads one config item by id, memoised for the life of the upload.
// A missing item is nil rather than an error: the id came from a stored choice
// or a parent reference, and either can name something since deleted.
func (r *Resolver) configItem(ctx context.Context, id uuid.UUID) (*dutymodels.ConfigItem, error) {
	if cached, found := r.items[id]; found {
		return cached, nil
	}
	items, err := r.client.GetCatalogItems(ctx, []string{id.String()})
	if err != nil {
		return nil, fmt.Errorf("read the catalog item %s: %w", id, err)
	}
	r.items[id] = nil
	for _, item := range items {
		if item.ID == id {
			r.items[id] = &item
		}
	}
	return r.items[id], nil
}

// identifies confirms the server's candidate really carries the identity, which
// the LIKE narrowing only approximates.
func identifies(item dutymodels.ConfigItem, candidate Candidate) bool {
	if candidate.Type != "" && !strings.EqualFold(derefString(item.Type), candidate.Type) {
		return false
	}
	if strings.EqualFold(derefString(item.Name), candidate.Value) {
		return true
	}
	for _, external := range item.ExternalID {
		if strings.EqualFold(external, candidate.Value) {
			return true
		}
	}
	return false
}

func findingRef(scan api.Scan, finding api.Finding) string {
	id := finding.ScanID
	if id == "" {
		id = scan.ID
	}
	return fmt.Sprintf("%s#%d", id, finding.LineNo)
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
