package entities

import (
	"context"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/entity"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/store"
)

// registerResource exposes the estate the scans examined.
//
// ToolGroup("inventory"), beside target/discover/probe rather than beside scan:
// a scan is an event and a resource is state. A run is deleted when its
// artifacts are pruned; the bucket it looked at is not.
//
// Deliberately not Parent("target"). Nesting generates both
// /target/{target}/resource and /target/resource/{id}, the ambiguous pair
// registerFinding already documents — and the relationship is wrong anyway: one
// target covers many accounts and one account is reachable through two targets,
// so a resource is not owned by a target. The drill-down is
// `resource list --target <id>`.
func (r *Registry) registerResource() {
	clicky.NewEntity[api.Resource, store.ResourceOpts, api.Resource]("resource").
		Aliases("resources").
		ToolGroup("inventory").
		// Paged, and the only entity that is. --limit plus "narrow it with a
		// filter" works when the reader already knows what to narrow to: a
		// findings list arrives scoped to one run. This list opens cold, and
		// the first question asked of it is "what have I got" — to which the
		// first hundred of an unstated number is not a partial answer but a
		// wrong one. Targets need no page because they are curated by hand and
		// bounded by human effort; resources are enumerated by a machine and
		// bounded by nothing.
		ListPagedWithContext(pagedResources(bind(r, (*store.Store).ListResourcesPaged))).
		GetWithContext(bind(r, (*store.Store).GetResource)).
		Filters(r.resourceFilters()...).
		WithAction(entity.TypedActionWithContext("config", resourceConfigFlags{}, r.resourceConfig).
			WithMethod("GET").WithShort("Read the linked Mission Control catalog item")).
		WithAction(entity.TypedActionWithContext("unlink-config", resourceConfigFlags{}, r.unlinkResourceConfig).
			WithShort("Remove the stored Mission Control config link")).
		WithAction(entity.TypedActionWithContext("sync", resourceSyncFlags{}, r.syncResources).
			WithOptionalID().WithShort("Sync current states for the selected resources to Mission Control")).
		WithAction(entity.TypedActionWithContext("mute", resourceMuteFlags{}, r.muteResource).
			WithShort("Mute findings on this exact resource")).
		Register()
}

// pagedResources restates the store's page as the framework's.
//
// The two are the same three fields with the same JSON tags, and the adapter
// exists only so neither internal/store nor internal/api has to import clicky.
// That boundary is worth an eight-line function: those packages are the wire
// contract and the persistence layer, and today neither knows the CLI framework
// exists.
func pagedResources(
	list func(context.Context, store.ResourceOpts) (api.ResourcePage, error),
) func(context.Context, store.ResourceOpts) (entity.PagedResult[api.Resource], error) {
	return func(ctx context.Context, opts store.ResourceOpts) (entity.PagedResult[api.Resource], error) {
		page, err := list(ctx, opts)
		if err != nil {
			return entity.PagedResult[api.Resource]{}, err
		}
		return entity.NewPagedResult(page.Data, page.Page.Limit, page.Page.Offset, page.Page.Total), nil
	}
}

// resourceFilters narrow the estate.
//
// The vocabularies come from the resources actually recorded rather than from
// any provider's catalogue of what could exist: the useful facets are the ones
// this estate has. `target` and `template` reuse the finding vocabularies
// instead of minting duplicates — they are the same values, and two queries
// that can disagree about one set of values is exactly what vocabulary.go
// exists to prevent.
func (r *Registry) resourceFilters() []clicky.Filter[store.ResourceOpts] {
	return []clicky.Filter[store.ResourceOpts]{
		filter[store.ResourceOpts]{key: "provider", label: "Provider", values: r.vocabulary(store.TargetProviders)},
		filter[store.ResourceOpts]{key: "account", label: "Account", values: r.vocabulary(store.ResourceAccounts)},
		// ⚠ `type` is in the UI's NEGATABLE set, so this renders as a tri-state
		// control that sends `!storage.googleapis.com/Bucket`. ResourceOpts.Type
		// honours the `!` through partitionTags — a filter that rendered an
		// exclusion the server read as a literal value would match nothing and
		// look like a working exclusion.
		filter[store.ResourceOpts]{key: "type", label: "Type", values: r.vocabulary(store.ResourceTypes)},
		filter[store.ResourceOpts]{key: "service", label: "Service", values: r.vocabulary(store.ResourceServices)},
		filter[store.ResourceOpts]{key: "region", label: "Region", values: r.vocabulary(store.ResourceRegions)},
		filter[store.ResourceOpts]{key: "engine", label: "Engine", values: r.vocabulary(store.ResourceEngines)},
		filter[store.ResourceOpts]{key: "tag", label: "Tag", values: r.vocabulary(store.ResourceTags)},
		filter[store.ResourceOpts]{key: "label", label: "Label", values: r.vocabulary(store.ResourceLabels)},
		filter[store.ResourceOpts]{key: "target", label: "Target", values: r.vocabulary(store.FindingTargets)},
		filter[store.ResourceOpts]{key: "kind", label: "Kind", values: fixed(
			api.KindAccount, api.KindCloudResource, api.KindArtifact, api.KindEndpoint)},
		filter[store.ResourceOpts]{key: "severity", label: "Severity", values: fixed(severityNames()...)},
		// Fixed rather than a vocabulary because it is not a column: it is the
		// three-way distinction recording passing checks creates, and nothing
		// in the data would suggest `unchecked` is a thing to ask for.
		filter[store.ResourceOpts]{key: "status", label: "Status", values: fixed(
			store.ResourceFailing, store.ResourceClean, store.ResourceUnchecked)},
		filter[store.ResourceOpts]{key: "state", label: "State", values: fixed(
			api.ResourcePresent, api.ResourceAbsent)},
		rangeFilter[store.ResourceOpts]{key: "first-seen", label: "First seen"},
		rangeFilter[store.ResourceOpts]{key: "last-seen", label: "Last seen"},
	}
}
