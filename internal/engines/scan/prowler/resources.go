package prowler

import (
	"encoding/json"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/configdb"
)

// ocsfResource is one entry of an OCSF record's `resources` array.
//
// Labels is kept raw because OCSF underspecifies it and providers disagree: GCP
// emits an empty array where an object is meant. Decoding that into a typed
// field would be a parse error, which would fail the whole report over a field
// nothing depends on.
type ocsfResource struct {
	Name   string          `json:"name"`
	UID    string          `json:"uid"`
	Type   string          `json:"type"`
	Region string          `json:"region"`
	Labels json.RawMessage `json:"labels"`
	Group  struct {
		Name string `json:"name"`
	} `json:"group"`
	Data struct {
		Details  string         `json:"details"`
		Metadata map[string]any `json:"metadata"`
	} `json:"data"`
}

// collectResources records every resource a record names, whatever its verdict.
//
// Every entry, not just the first: a check that fails against forty buckets
// names forty, and reading one is how thirty-nine used to leave no trace. The
// verdict, though, is attributed to the primary resource alone — a check has one
// subject and the rest are context, so counting a pass against all of them would
// resolve findings on resources the check never judged.
// subjects names what a record reports on, and the identity recon keys those
// rows by.
//
// One implementation for the rows a run emits and the references its findings
// carry. They have to agree exactly: a finding is linked to a resource by
// looking (provider, scope, uid) up among the rows the same run wrote, so a
// reference keyed even slightly differently resolves to nothing and the finding
// is recorded with no subject at all.
//
// They did diverge. The references took the provider from the argument the
// report was read with while the rows took it from the record, so a Kubernetes
// record inside a GCP audit produced a row keyed `kubernetes` and a reference
// keyed `gcp`, and the two never met.
func subjects(record ocsfRecord) (provider, scope string, resources []ocsfResource) {
	provider = recordProvider(record)
	scope = firstNonEmpty(record.Cloud.Account.UID, recordHost(record))
	resources = record.Resources
	// A check with nothing more specific to point at is about the account
	// itself, which is a subject recon records like any other.
	if len(resources) == 0 && scope != "" {
		resources = []ocsfResource{{UID: scope, Name: recordHost(record), Type: record.Cloud.Account.Type}}
	}
	return provider, scope, resources
}

// resourceRefs is how a finding names its subjects, complete enough to resolve.
//
// Built from the typed record rather than read back out of the preserved JSON
// and patched afterwards. OCSF carries only a uid on each entry of its
// resources array — the account sits once at the event level — so reading it
// back can never produce a whole key, and the patch that used to follow was the
// only thing making ingest work while every read stayed broken.
func resourceRefs(record ocsfRecord) []api.ResourceRef {
	provider, scope, resources := subjects(record)
	refs := make([]api.ResourceRef, 0, len(resources))
	for _, resource := range resources {
		if resource.UID == "" {
			continue
		}
		refs = append(refs, api.ResourceRef{
			Provider: provider, Scope: scope, UID: resource.UID,
			Name:    resource.Name,
			Type:    resource.Type,
			Service: resource.Group.Name,
			Region:  resource.Region,
		})
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

func (r *ocsfReport) collectResources(record ocsfRecord, targetID string) {
	provider, scope, resources := subjects(record)
	for index, resource := range resources {
		if resource.UID == "" {
			continue
		}
		key := api.ResourceKey{Provider: provider, Scope: scope, UID: resource.UID}
		existing, seen := r.resources[key]
		if !seen {
			existing = newResource(key, record, resource, targetID)
			r.order = append(r.order, key)
		}
		if index == 0 {
			switch {
			case record.StatusCode == "PASS":
				existing.Passed = append(existing.Passed, templateID(record, provider))
			case isSuppressed(record):
				existing.Suppressed = append(existing.Suppressed, templateID(record, provider))
			}
		}
		r.resources[key] = existing
	}
}

func newResource(key api.ResourceKey, record ocsfRecord, resource ocsfResource, targetID string) api.Resource {
	built := api.Resource{
		Provider: key.Provider,
		Scope:    key.Scope,
		UID:      key.UID,
		Kind:     api.KindCloudResource,
		Type:     resource.Type,
		Name:     resource.Name,
		Service:  resource.Group.Name,
		Region:   firstNonEmpty(resource.Region, record.Cloud.Region),

		TargetID:    targetID,
		AccountName: record.Cloud.Account.Name,
		OrgUID:      record.Cloud.Org.UID,
		OrgName:     record.Cloud.Org.Name,

		Labels:   resourceLabels(resource),
		Metadata: resource.Data.Metadata,
	}

	// Prowler names the account itself whenever a check has nothing more
	// specific to point at, and types it with whichever service the check
	// belongs to — so one project arrives as an APIKeys Key, a Compute Project,
	// a ResourceManager Project and an AccessApproval setting across four
	// checks. Recognising the case is what keeps the project one row with one
	// stable type instead of four rows that swap places between runs.
	if resource.UID == key.Scope {
		built.Kind = api.KindAccount
		built.Type = firstNonEmpty(record.Cloud.Account.Type, resource.Type)
		built.Name = firstNonEmpty(record.Cloud.Account.Name, resource.Name)
	}

	built.Tags = resourceTags(built)
	built.ConfigType = configdb.ConfigType(built.Provider, built.Type)
	// Both the uid and the name, because neither is reliably the identity
	// config-db keyed on: for a firewall it is the numeric uid, and for a
	// service account it is the `projects/…/serviceAccounts/…` name while the
	// uid — the email — is only an alias.
	built.ExternalIDs = configdb.ExternalIDs(built.UID, built.Name)
	return built
}

// resourceTags are the same key:value strings a finding carries, so the two
// listings filter on one vocabulary rather than two.
func resourceTags(resource api.Resource) api.StringList {
	set := map[string]struct{}{}
	appendTag(set, "provider", resource.Provider)
	appendTag(set, "service", resource.Service)
	appendTag(set, "resource-type", resource.Type)
	appendTag(set, "region", resource.Region)
	appendTag(set, "account", resource.Scope)
	return api.StringList(sortedTags(set))
}

// resourceLabels decodes the provider's own labels, tolerating both shapes OCSF
// is used with. A value that is neither is dropped rather than failing the run.
func resourceLabels(resource ocsfResource) map[string]string {
	if len(resource.Labels) == 0 {
		return nil
	}
	var object map[string]string
	if err := json.Unmarshal(resource.Labels, &object); err == nil && len(object) > 0 {
		return object
	}
	var list []string
	if err := json.Unmarshal(resource.Labels, &list); err == nil && len(list) > 0 {
		labels := make(map[string]string, len(list))
		for _, entry := range list {
			key, value, found := cutLabel(entry)
			if found {
				labels[key] = value
			}
		}
		if len(labels) > 0 {
			return labels
		}
	}
	return nil
}

func templateID(record ocsfRecord, provider string) string {
	return provider + "/" + record.Metadata.EventCode
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
