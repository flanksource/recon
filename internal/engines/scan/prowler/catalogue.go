package prowler

import (
	"fmt"
	"sort"
	"strings"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
)

const previewLimit = 200

var _ scan.Catalogue = Engine{}

func (e Engine) Templates() ([]api.Template, error) {
	loaded, err := e.metadataCatalogue()
	if err != nil {
		return nil, err
	}
	return templateDocuments(loaded.Checks), nil
}

func (e Engine) Corpus() api.EngineTemplates {
	return api.EngineTemplates{
		Version:      catalog.ExpectedManifest.Version,
		Count:        catalog.ExpectedManifest.CheckCount,
		Path:         "embedded:prowler/catalog.generated.json.xz",
		ItemLabel:    "check",
		ProfileLabel: "compliance framework",
	}
}

func (e Engine) Preview(config map[string]any) (api.TemplatePreview, error) {
	if err := e.Spec().ValidateConfig(config); err != nil {
		return api.TemplatePreview{}, err
	}
	selected, caveats, err := e.selectChecks(config)
	if err != nil {
		return api.TemplatePreview{}, err
	}
	documents := templateDocuments(selected)
	preview := api.TemplatePreview{
		Engine: EngineName, Total: len(documents), BySeverity: map[string]int{}, ByType: map[string]int{},
		Templates: documents[:min(len(documents), previewLimit)], Truncated: len(documents) > previewLimit,
		Caveats: caveats,
	}
	tags := map[string]int{}
	for _, template := range documents {
		preview.BySeverity[template.Severity]++
		preview.ByType[template.Type]++
		for _, tag := range template.Tags {
			tags[tag]++
		}
	}
	preview.ByTag = topTemplateTags(tags)
	return preview, nil
}

func (e Engine) Select(config map[string]any) ([]api.Template, error) {
	if err := e.Spec().ValidateConfig(config); err != nil {
		return nil, err
	}
	checks, _, err := e.selectChecks(config)
	return templateDocuments(checks), err
}

func (e Engine) selectChecks(config map[string]any) ([]catalog.Check, []string, error) {
	loaded, err := e.metadataCatalogue()
	if err != nil {
		return nil, nil, err
	}
	provider, _ := config["provider"].(string)
	selected, caveats, err := primarySelection(loaded, provider, config)
	if err != nil {
		return nil, nil, err
	}
	excludedChecks, err := checkSet(loaded, provider, stringValues(config["excluded-checks"]))
	if err != nil {
		return nil, nil, err
	}
	excludedServices := valueSet(stringValues(config["excluded-services"]))
	// severities, not severity: the profile schema names this option after what
	// it holds, and "severity" is only Prowler's argparse destination. Reading
	// the destination here matched nothing, so the preview reported every check
	// a profile selected as if the severity filter were unset.
	severities := lowerSet(stringValues(config["severities"]))
	filtered := selected[:0]
	for _, check := range selected {
		if excludedChecks[check.ID] || excludedServices[check.Service] {
			continue
		}
		if len(severities) > 0 && !severities[strings.ToLower(check.Severity)] {
			continue
		}
		filtered = append(filtered, check)
	}
	return filtered, caveats, nil
}

func primarySelection(loaded *catalog.Catalog, provider string, config map[string]any) ([]catalog.Check, []string, error) {
	if compliance := stringValues(config["compliance"]); len(compliance) > 0 {
		selected, caveats := []catalog.Check{}, []string{}
		seen := map[string]bool{}
		for _, id := range compliance {
			profile, ok := loaded.Profile(provider, id)
			if !ok {
				return nil, nil, fmt.Errorf("unknown Prowler compliance %s/%s", provider, id)
			}
			checks, _ := loaded.ChecksForProfile(provider, id)
			selected = appendUniqueChecks(selected, checks, seen)
			if len(profile.MissingCheckKeys) > 0 {
				caveats = append(caveats, fmt.Sprintf(
					"%s references %d checks absent from the pinned Prowler corpus", id, len(profile.MissingCheckKeys)))
			}
		}
		return selected, caveats, nil
	}
	if checks := stringValues(config["checks"]); len(checks) > 0 {
		return checksByID(loaded, provider, checks)
	}
	return filterProviderChecks(loaded, provider, config)
}

func checksByID(loaded *catalog.Catalog, provider string, ids []string) ([]catalog.Check, []string, error) {
	selected := make([]catalog.Check, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		check, ok := loaded.Check(provider, id)
		if !ok {
			check, ok = checkByAlias(loaded, provider, id)
		}
		if !ok {
			return nil, nil, fmt.Errorf("unknown Prowler check %s/%s", provider, id)
		}
		selected = appendUniqueChecks(selected, []catalog.Check{check}, seen)
	}
	return selected, nil, nil
}

func filterProviderChecks(loaded *catalog.Catalog, provider string, config map[string]any) ([]catalog.Check, []string, error) {
	services := valueSet(stringValues(config["services"]))
	categories := valueSet(stringValues(config["categories"]))
	groups := valueSet(stringValues(config["resource-groups"]))
	selected := []catalog.Check{}
	for _, check := range loaded.Checks {
		if check.Provider != provider {
			continue
		}
		if len(services) > 0 && !services[check.Service] {
			continue
		}
		if len(categories) > 0 && !containsAny(check.Categories, categories) {
			continue
		}
		if len(groups) > 0 && !groups[check.ResourceGroup] {
			continue
		}
		selected = append(selected, check)
	}
	return selected, nil, nil
}

func checkSet(loaded *catalog.Catalog, provider string, ids []string) (map[string]bool, error) {
	selected, _, err := checksByID(loaded, provider, ids)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for _, check := range selected {
		set[check.ID] = true
	}
	return set, nil
}

func checkByAlias(loaded *catalog.Catalog, provider, alias string) (catalog.Check, bool) {
	for _, check := range loaded.Checks {
		if check.Provider == provider && contains(check.Aliases, alias) {
			return check, true
		}
	}
	return catalog.Check{}, false
}

func appendUniqueChecks(out, values []catalog.Check, seen map[string]bool) []catalog.Check {
	for _, check := range values {
		if !seen[check.Key] {
			seen[check.Key] = true
			out = append(out, check)
		}
	}
	return out
}

func templateDocuments(checks []catalog.Check) []api.Template {
	documents := make([]api.Template, 0, len(checks))
	for _, check := range checks {
		documents = append(documents, api.Template{
			ID: check.Key, Name: check.Title, Engine: EngineName, Provider: check.Provider,
			Severity: check.Severity, Type: check.Service, Risk: check.Risk, ResourceType: check.ResourceType,
			Tags: checkTags(check), Authors: []string{}, Path: check.Source,
			Description: check.Description, Remediation: check.Remediation.Text,
			Reference: append([]string(nil), check.References...),
			Metadata:  checkMetadata(check),
		})
	}
	return documents
}

func checkMetadata(check catalog.Check) map[string]any {
	code := make(map[string]string, len(check.Remediation.Code))
	for name, value := range check.Remediation.Code {
		code[name] = value
	}
	return map[string]any{
		"aliases":            append([]string(nil), check.Aliases...),
		"subService":         check.SubService,
		"resourceGroup":      check.ResourceGroup,
		"resourceIdTemplate": check.ResourceIDTemplate,
		"categories":         append([]string(nil), check.Categories...),
		"checkTypes":         append([]string(nil), check.CheckTypes...),
		"remediation": map[string]any{
			"text": check.Remediation.Text, "url": check.Remediation.URL, "code": code,
		},
		"dependsOn": append([]string(nil), check.DependsOn...),
		"relatedTo": append([]string(nil), check.RelatedTo...),
		"notes":     check.Notes,
	}
}

func checkTags(check catalog.Check) []string {
	tags := []string{"provider:" + check.Provider, "service:" + check.Service}
	for _, category := range check.Categories {
		tags = append(tags, "category:"+category)
	}
	for _, checkType := range check.CheckTypes {
		tags = append(tags, "check-type:"+checkType)
	}
	if check.ResourceGroup != "" {
		tags = append(tags, "resource-group:"+check.ResourceGroup)
	}
	if check.ResourceType != "" {
		tags = append(tags, "resource-type:"+check.ResourceType)
	}
	sort.Strings(tags)
	return tags
}

func topTemplateTags(counts map[string]int) []api.TemplateTag {
	values := make([]api.TemplateTag, 0, len(counts))
	for tag, count := range counts {
		values = append(values, api.TemplateTag{Tag: tag, Count: count})
	}
	sort.Slice(values, func(i, j int) bool {
		if values[i].Count != values[j].Count {
			return values[i].Count > values[j].Count
		}
		return values[i].Tag < values[j].Tag
	})
	return values[:min(len(values), 25)]
}

func stringValues(value any) []string {
	values, _ := stringSlice(value)
	return values
}

func valueSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func lowerSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[strings.ToLower(value)] = true
	}
	return set
}

func containsAny(values []string, selected map[string]bool) bool {
	for _, value := range values {
		if selected[value] {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
