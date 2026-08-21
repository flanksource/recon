package catalog

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
)

type providerComplianceSource struct {
	Framework    string                      `json:"Framework"`
	Name         string                      `json:"Name"`
	Version      string                      `json:"Version"`
	Provider     string                      `json:"Provider"`
	Description  string                      `json:"Description"`
	Requirements []providerRequirementSource `json:"Requirements"`
}

type providerRequirementSource struct {
	ID          string           `json:"Id"`
	Description string           `json:"Description"`
	Checks      []string         `json:"Checks"`
	Attributes  []map[string]any `json:"Attributes"`
}

func parseProviderCompliance(filename string, data []byte) ([]Profile, error) {
	var input providerComplianceSource
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parse compliance %s: %w", filename, err)
	}
	provider := strings.ToLower(input.Provider)
	parts := strings.Split(filename, "/")
	if len(parts) != 4 || parts[2] != provider {
		return nil, fmt.Errorf("compliance %s: provider %q does not match its path", filename, input.Provider)
	}
	if input.Framework == "" || input.Name == "" || provider == "" || len(input.Requirements) == 0 {
		return nil, fmt.Errorf("compliance %s: framework, name, provider, and requirements are required", filename)
	}

	complianceID := strings.TrimSuffix(path.Base(filename), path.Ext(filename))
	profile := Profile{
		Key:          profileKey(provider, complianceID),
		Name:         profileName(provider, complianceID),
		Provider:     provider,
		ComplianceID: complianceID,
		Framework:    input.Framework,
		Title:        input.Name,
		Version:      input.Version,
		Description:  input.Description,
		Source:       filename,
		Controls:     make([]Control, 0, len(input.Requirements)),
	}
	for _, requirement := range input.Requirements {
		if requirement.ID == "" {
			return nil, fmt.Errorf("compliance %s: requirement ID is required", filename)
		}
		status := assessmentStatus(requirement.Attributes)
		keys := qualify(provider, requirement.Checks)
		name := requirement.Description
		if name == "" {
			name = attributeText(requirement.Attributes, "SubSection", "Subsection", "Section")
		}
		if name == "" {
			name = requirement.ID
		}
		control := Control{
			ID:               requirement.ID,
			Name:             name,
			Description:      attributeDescription(requirement.Attributes, name),
			AssessmentStatus: status,
			Attributes:       requirement.Attributes,
			CheckKeys:        keys,
		}
		profile.Controls = append(profile.Controls, control)
		profile.CheckKeys = append(profile.CheckKeys, keys...)
		if strings.EqualFold(status, "manual") {
			profile.ManualControls++
		}
		if len(keys) == 0 {
			profile.UnmappedControls++
		}
	}
	profile.CheckKeys = unique(profile.CheckKeys)
	return []Profile{profile}, nil
}

type sharedComplianceSource struct {
	Framework    string                    `json:"framework"`
	Name         string                    `json:"name"`
	Version      string                    `json:"version"`
	Description  string                    `json:"description"`
	Requirements []sharedRequirementSource `json:"requirements"`
}

type sharedRequirementSource struct {
	ID                 string                    `json:"id"`
	Name               string                    `json:"name"`
	Description        string                    `json:"description"`
	Attributes         map[string]any            `json:"attributes"`
	Checks             map[string][]string       `json:"checks"`
	ConfigRequirements []configRequirementSource `json:"config_requirements"`
}

type configRequirementSource struct {
	Check    string `json:"Check"`
	Provider string `json:"Provider"`
	Key      string `json:"ConfigKey"`
	Operator string `json:"Operator"`
	Value    any    `json:"Value"`
}

func parseSharedCompliance(filename string, data []byte) ([]Profile, error) {
	var input sharedComplianceSource
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parse compliance %s: %w", filename, err)
	}
	if input.Framework == "" || input.Name == "" || len(input.Requirements) == 0 {
		return nil, fmt.Errorf("compliance %s: framework, name, and requirements are required", filename)
	}
	providers := map[string]struct{}{}
	for _, requirement := range input.Requirements {
		for provider := range requirement.Checks {
			providers[strings.ToLower(provider)] = struct{}{}
		}
	}
	if len(providers) == 0 {
		return nil, fmt.Errorf("compliance %s: shared framework has no provider mappings", filename)
	}

	complianceID := strings.TrimSuffix(path.Base(filename), path.Ext(filename))
	profiles := make([]Profile, 0, len(providers))
	for _, provider := range sortedKeys(providers) {
		profile, err := projectSharedProfile(filename, complianceID, provider, input)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

func projectSharedProfile(filename, complianceID, provider string, input sharedComplianceSource) (Profile, error) {
	profile := Profile{
		Key:          profileKey(provider, complianceID),
		Name:         profileName(provider, complianceID),
		Provider:     provider,
		ComplianceID: complianceID,
		Framework:    input.Framework,
		Title:        input.Name,
		Version:      input.Version,
		Description:  input.Description,
		Source:       filename,
		Controls:     make([]Control, 0, len(input.Requirements)),
	}
	for _, requirement := range input.Requirements {
		if requirement.ID == "" {
			return Profile{}, fmt.Errorf("compliance %s: shared requirement ID is required", filename)
		}
		keys := qualify(provider, providerChecks(requirement.Checks, provider))
		name := requirement.Name
		if name == "" {
			name = requirement.Description
		}
		if name == "" {
			name = requirement.ID
		}
		control := Control{
			ID:          requirement.ID,
			Name:        name,
			Description: requirement.Description,
			Attributes:  []map[string]any{requirement.Attributes},
			CheckKeys:   keys,
		}
		for _, config := range requirement.ConfigRequirements {
			if !strings.EqualFold(config.Provider, provider) {
				continue
			}
			control.ConfigRequirements = append(control.ConfigRequirements, ConfigRequirement{
				CheckKey: checkKey(provider, config.Check),
				Key:      config.Key,
				Operator: config.Operator,
				Value:    config.Value,
			})
		}
		profile.Controls = append(profile.Controls, control)
		profile.CheckKeys = append(profile.CheckKeys, keys...)
		if len(keys) == 0 {
			profile.UnmappedControls++
		}
	}
	profile.CheckKeys = unique(profile.CheckKeys)
	return profile, nil
}

func providerChecks(checks map[string][]string, provider string) []string {
	for name, ids := range checks {
		if strings.EqualFold(name, provider) {
			return ids
		}
	}
	return nil
}

func assessmentStatus(attributes []map[string]any) string {
	statuses := []string{}
	for _, attribute := range attributes {
		if status, ok := attribute["AssessmentStatus"].(string); ok {
			statuses = append(statuses, status)
		}
	}
	statuses = unique(statuses)
	return strings.Join(statuses, ", ")
}

func attributeDescription(attributes []map[string]any, fallback string) string {
	if description := attributeText(attributes, "Description"); description != "" {
		return description
	}
	return fallback
}

func attributeText(attributes []map[string]any, keys ...string) string {
	for _, key := range keys {
		for _, attribute := range attributes {
			if value, ok := attribute[key].(string); ok && value != "" {
				return value
			}
		}
	}
	return ""
}

func sortProfiles(profiles []Profile) {
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Key < profiles[j].Key })
}
