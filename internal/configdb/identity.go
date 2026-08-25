// Package configdb projects a resource recon saw onto the identity Mission
// Control's catalog stores it under.
//
// The two systems describe the same estate from different angles and would
// otherwise never meet: recon learns about a GCP firewall from Prowler's OCSF
// report, config-db learns about it from Cloud Asset Inventory, and nothing
// makes the two records recognisable as the same thing. They are, though —
// Prowler's `resources[].type` is literally the Cloud Asset Inventory asset type
// config-db consumes — so the projection is a transform rather than a guess.
//
// It exists to resolve, never to create. config_items has one unique key, its
// id, and Mission Control's upstream push upserts on it with UpdateAll, so a
// pushed item whose id collided with a scraped one would overwrite the real
// record wholesale. Recon therefore mints identities to *look configs up by* and
// leaves the catalog to whoever scrapes it.
package configdb

import "strings"

// ConfigType is the config item type config-db would have stored a resource
// under, or empty when recon cannot say.
//
// Empty is a real answer and the common one outside GCP. The transform is exact
// for a Cloud Asset Inventory asset type because config-db derives its own type
// from that same string; for the other providers it recognises a type already in
// config-db's shape and declines everything else. A wrong type is worse than no
// type: it scopes a catalog lookup to the wrong rows and turns a miss into a
// confident mismatch.
func ConfigType(provider, resourceType string) string {
	resourceType = strings.TrimSpace(resourceType)
	if resourceType == "" {
		return ""
	}

	switch strings.ToLower(provider) {
	case "gcp":
		return gcpConfigType(resourceType)
	case "aws":
		return awsConfigType(resourceType)
	case "azure":
		return azureConfigType(resourceType)
	case "kubernetes", "k8s":
		return kubernetesConfigType(resourceType)
	case "github":
		return githubConfigType(resourceType)
	default:
		return ""
	}
}

// gcpConfigType reproduces config-db's parseGCPConfigClass.
//
// A Cloud Asset Inventory asset type is `<service>.googleapis.com/<Resource>`.
// config-db keeps the resource half, disambiguating with an override table
// wherever a bare resource name would collide across services — `Instance` is a
// Compute VM, an AlloyDB instance and a Cloud SQL instance — and prefixes the
// result with `GCP::`.
func gcpConfigType(assetType string) string {
	if _, _, ok := splitAssetType(assetType); !ok {
		return ""
	}
	if override, known := gcpTypeOverrides[assetType]; known {
		return "GCP::" + override
	}
	_, resource, _ := splitAssetType(assetType)
	return "GCP::" + resource
}

// splitAssetType divides a Cloud Asset Inventory asset type into its service and
// resource halves. A value that is not one is reported rather than coerced:
// config-db returns "GCP::"+assetType in that case, which is a type no catalog
// row carries, so recon declines instead of minting a lookup that cannot hit.
func splitAssetType(assetType string) (service, resource string, ok bool) {
	service, resource, ok = strings.Cut(assetType, ".googleapis.com/")
	if !ok || service == "" || resource == "" || strings.Contains(resource, "/") {
		return "", "", false
	}
	return service, resource, true
}

// awsConfigType passes through a type already in config-db's vocabulary.
//
// config-db uses AWS Config's own resource types verbatim, so a value that is
// one needs no transform. It is checked against the generated vocabulary rather
// than by its `AWS::` prefix because the prefix is easy to produce and the
// vocabulary is what actually exists — and because the list has entries no rule
// would predict, such as AWS::::Account with its empty service segment and
// AWS::EBS::Volume where AWS Config itself says EC2.
func awsConfigType(resourceType string) string {
	if _, known := awsTypes[resourceType]; known {
		return resourceType
	}
	return ""
}

// azureConfigType prefixes an ARM resource type.
//
// config-db stores `Azure::` plus the raw ARM type, which is always
// `<Namespace>/<resource>` with a `Microsoft.`-style namespace. Anything else is
// not an ARM type and gets no answer.
func azureConfigType(resourceType string) string {
	if strings.HasPrefix(resourceType, "Azure::") {
		return resourceType
	}
	namespace, resource, ok := strings.Cut(resourceType, "/")
	if !ok || !strings.Contains(namespace, ".") || resource == "" {
		return ""
	}
	return "Azure::" + resourceType
}

// kubernetesConfigType prefixes a Kind.
//
// Only a bare Kind — config-db builds the type from obj.GetKind(), so anything
// carrying a group, a slash or a version is not what it stores. The Crossplane
// and MissionControl prefixes it also mints are decided by apiVersion, which a
// resource type alone does not carry, so they are deliberately not guessed here.
func kubernetesConfigType(kind string) string {
	if strings.HasPrefix(kind, "Kubernetes::") {
		return kind
	}
	if kind == "" || strings.ContainsAny(kind, "/.: ") {
		return ""
	}
	return "Kubernetes::" + kind
}

func githubConfigType(resourceType string) string {
	if _, known := githubTypes[resourceType]; known {
		return resourceType
	}
	if mapped, known := githubTypeAliases[strings.ToLower(resourceType)]; known {
		return mapped
	}
	return ""
}

// ScraperLess reports a config type config-db stores without a scraper id.
//
// It matters to a lookup: for these, config-db's own Find drops the scraper from
// the predicate, so a caller scoping by one would exclude the very rows it wants.
func ScraperLess(configType string) bool {
	_, ok := scraperLessTypes[configType]
	return ok
}

// ExternalIDs renders the identities a config item could be found by, in
// config-db's own normalised form: lowercased, trimmed, deduplicated, and with
// empties dropped, which is exactly what NewConfigItemFromResult stores.
//
// Every candidate is offered rather than one chosen, because no single field is
// reliably config-db's primary identity. For a GCP firewall the primary is the
// numeric resource id, which Prowler reports as the resource uid; for a service
// account it is `projects/…/serviceAccounts/…`, which Prowler reports as the
// resource *name* while its uid is the email config-db keeps only as an alias.
// Choosing either field alone gets one of those two cases wrong.
func ExternalIDs(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	ids := make([]string, 0, len(values))
	for _, value := range values {
		normalised := NormalizeExternalID(value)
		if normalised == "" {
			continue
		}
		if _, duplicate := seen[normalised]; duplicate {
			continue
		}
		seen[normalised] = struct{}{}
		ids = append(ids, normalised)
	}
	if len(ids) == 0 {
		return nil
	}
	return ids
}

// NormalizeExternalID matches config-db's NormalizeExternalID exactly. The
// catalog stores external ids already lowercased, so a lookup that skipped this
// would miss every row whose identity carried a capital.
func NormalizeExternalID(externalID string) string {
	return strings.ToLower(strings.TrimSpace(externalID))
}
