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
	// Note records a finer identity that was skipped because it matched more
	// than one config item. Ambiguity is not a miss, but it must not be silent.
	Note string
}

// resolveLimit bounds a candidate lookup. One match is the answer and two are
// already ambiguous, so a page beyond a handful buys nothing.
const resolveLimit = 10

type lookup struct {
	match     *Match
	ambiguous []string
}

// Resolver maps recon identities onto catalog config items. Lookups are
// memoised for the life of an upload: a scan of one host produces many findings
// that all resolve to the same config item.
type Resolver struct {
	client *sdk.Client
	// Agent scopes the search to one agent's configs, or every agent when empty.
	Agent string

	cache map[string]lookup
}

func NewResolver(client *sdk.Client) *Resolver {
	return &Resolver{client: client, cache: map[string]lookup{}}
}

// Resolve returns the config item a finding belongs to, or the report of why
// nothing could be found for it.
func (r *Resolver) Resolve(ctx context.Context, options ResolveOptions) (*Match, *api.InsightUnresolved, error) {
	var tried []string
	var skipped []string

	for _, candidate := range candidates(options.State, options.Target) {
		tried = append(tried, candidate.Value)

		found, err := r.lookupCandidate(ctx, candidate)
		if err != nil {
			return nil, nil, err
		}
		if len(found.ambiguous) > 0 {
			skipped = append(skipped, fmt.Sprintf("%s matched %d config items (%s)",
				candidate.Value, len(found.ambiguous), strings.Join(found.ambiguous, ", ")))
			continue
		}
		if found.match == nil {
			continue
		}

		match := *found.match
		match.MatchedOn = candidate.Value
		match.RolledUp = candidate.Scope
		match.Note = strings.Join(skipped, "; ")
		return &match, nil, nil
	}

	reason := "no catalog config item matches the resource, its account, cluster or target"
	if len(skipped) > 0 {
		reason = strings.Join(skipped, "; ")
	}
	if len(tried) == 0 {
		reason = "the finding carries no identity to resolve against"
	}
	return nil, &api.InsightUnresolved{
		Finding:  findingRef(options.State.Scan, options.State.Finding),
		Host:     options.State.Resource.Name,
		Severity: options.State.Finding.SeverityLevel(),
		Tried:    tried,
		Reason:   reason,
	}, nil
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
	cacheKey := r.Agent + "\x00" + candidate.Type + "\x00" + candidate.Value
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
			Agent:  r.Agent,
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
		for _, item := range exact {
			result.ambiguous = append(result.ambiguous, item.ID.String())
		}
	}
	r.cache[cacheKey] = result
	return result, nil
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
