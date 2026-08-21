// Package catalog normalizes Prowler's provider, compliance, and check metadata.
package catalog

import (
	"fmt"
	"sort"
	"strings"
)

const (
	PinnedCommit   = "ba564af4f46fd7c4908d34798687eda36b88398c"
	ProwlerVersion = "5.40.0"
)

var ExpectedManifest = Manifest{
	Version:                ProwlerVersion,
	SourceCommit:           PinnedCommit,
	ProviderCount:          23,
	StaticProviderCount:    20,
	DynamicProviderCount:   3,
	CheckCount:             1586,
	ComplianceFileCount:    111,
	ProfileProjectionCount: 141,
}

type Manifest struct {
	Version                string `json:"version"`
	SourceCommit           string `json:"sourceCommit"`
	ProviderCount          int    `json:"providerCount"`
	StaticProviderCount    int    `json:"staticProviderCount"`
	DynamicProviderCount   int    `json:"dynamicProviderCount"`
	CheckCount             int    `json:"checkCount"`
	ComplianceFileCount    int    `json:"complianceFileCount"`
	ProfileProjectionCount int    `json:"profileProjectionCount"`
	Digest                 string `json:"digest"`
}

type Catalog struct {
	Manifest  Manifest   `json:"manifest"`
	Providers []Provider `json:"providers"`
	Profiles  []Profile  `json:"profiles"`
	Checks    []Check    `json:"checks"`

	providersByID map[string]int
	profilesByKey map[string]int
	checksByKey   map[string]int
}

type Provider struct {
	ID           string `json:"id"`
	Static       bool   `json:"static"`
	CheckCount   int    `json:"checkCount"`
	ProfileCount int    `json:"profileCount"`
}

type Profile struct {
	Key              string    `json:"key"`
	Name             string    `json:"name"`
	Provider         string    `json:"provider"`
	ComplianceID     string    `json:"complianceId"`
	Framework        string    `json:"framework"`
	Title            string    `json:"title"`
	Version          string    `json:"version"`
	Description      string    `json:"description"`
	Source           string    `json:"source"`
	Controls         []Control `json:"controls"`
	CheckKeys        []string  `json:"checkKeys"`
	MissingCheckKeys []string  `json:"missingCheckKeys,omitempty"`
	ManualControls   int       `json:"manualControls"`
	UnmappedControls int       `json:"unmappedControls"`
}

func (p Profile) Config() map[string]any {
	return map[string]any{
		"provider":   p.Provider,
		"compliance": []any{p.ComplianceID},
	}
}

type BuiltInProfile struct {
	Name    string
	Comment string
	Config  map[string]any
}

type Control struct {
	ID                 string              `json:"id"`
	Name               string              `json:"name"`
	Description        string              `json:"description"`
	AssessmentStatus   string              `json:"assessmentStatus,omitempty"`
	Attributes         []map[string]any    `json:"attributes,omitempty"`
	ConfigRequirements []ConfigRequirement `json:"configRequirements,omitempty"`
	CheckKeys          []string            `json:"checkKeys"`
	MissingCheckKeys   []string            `json:"missingCheckKeys,omitempty"`
}

type ConfigRequirement struct {
	CheckKey string `json:"checkKey"`
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}

type Check struct {
	Key                string      `json:"key"`
	ID                 string      `json:"id"`
	Provider           string      `json:"provider"`
	Title              string      `json:"title"`
	Aliases            []string    `json:"aliases,omitempty"`
	Severity           string      `json:"severity"`
	Service            string      `json:"service"`
	SubService         string      `json:"subService,omitempty"`
	CheckTypes         []string    `json:"checkTypes,omitempty"`
	ResourceType       string      `json:"resourceType"`
	ResourceGroup      string      `json:"resourceGroup,omitempty"`
	ResourceIDTemplate string      `json:"resourceIdTemplate,omitempty"`
	Categories         []string    `json:"categories"`
	Description        string      `json:"description"`
	Risk               string      `json:"risk"`
	Remediation        Remediation `json:"remediation"`
	References         []string    `json:"references,omitempty"`
	DependsOn          []string    `json:"dependsOn,omitempty"`
	RelatedTo          []string    `json:"relatedTo,omitempty"`
	Notes              string      `json:"notes,omitempty"`
	Source             string      `json:"source"`
}

type Remediation struct {
	Text string            `json:"text"`
	URL  string            `json:"url,omitempty"`
	Code map[string]string `json:"code,omitempty"`
}

func (c *Catalog) Provider(id string) (Provider, bool) {
	i, ok := c.providersByID[id]
	if !ok {
		return Provider{}, false
	}
	return c.Providers[i], true
}

func (c *Catalog) Profile(provider, complianceID string) (Profile, bool) {
	i, ok := c.profilesByKey[profileKey(provider, complianceID)]
	if !ok {
		return Profile{}, false
	}
	return c.Profiles[i], true
}

func (c *Catalog) Check(provider, checkID string) (Check, bool) {
	i, ok := c.checksByKey[checkKey(provider, checkID)]
	if !ok {
		return Check{}, false
	}
	return c.Checks[i], true
}

func (c *Catalog) ChecksForProfile(provider, complianceID string) ([]Check, error) {
	profile, ok := c.Profile(provider, complianceID)
	if !ok {
		return nil, fmt.Errorf("unknown prowler profile %s", profileKey(provider, complianceID))
	}
	checks := make([]Check, 0, len(profile.CheckKeys))
	for _, key := range profile.CheckKeys {
		checks = append(checks, c.Checks[c.checksByKey[key]])
	}
	return checks, nil
}

func (c *Catalog) BuiltInProfiles() []BuiltInProfile {
	profiles := make([]BuiltInProfile, 0, len(c.Profiles))
	for _, profile := range c.Profiles {
		profiles = append(profiles, BuiltInProfile{
			Name:    profile.Name,
			Comment: strings.TrimSpace(profile.Title + " " + profile.Version),
			Config:  profile.Config(),
		})
	}
	return profiles
}

func (c *Catalog) ProviderIDs() []string {
	return collect(c.Providers, func(provider Provider) string { return provider.ID })
}

func (c *Catalog) ComplianceIDs(provider string) []string {
	values := []string{}
	for _, profile := range c.Profiles {
		if profile.Provider == provider {
			values = append(values, profile.ComplianceID)
		}
	}
	return unique(values)
}

func (c *Catalog) CheckIDs(provider string) []string {
	return checkValues(c, provider, func(check Check) string { return check.ID })
}

func (c *Catalog) Services(provider string) []string {
	return checkValues(c, provider, func(check Check) string { return check.Service })
}

func (c *Catalog) Categories(provider string) []string {
	values := []string{}
	for _, check := range c.Checks {
		if check.Provider == provider {
			values = append(values, check.Categories...)
		}
	}
	return unique(values)
}

func (c *Catalog) ResourceGroups(provider string) []string {
	return checkValues(c, provider, func(check Check) string { return check.ResourceGroup })
}

func checkValues(c *Catalog, provider string, value func(Check) string) []string {
	values := []string{}
	for _, check := range c.Checks {
		if check.Provider == provider && value(check) != "" {
			values = append(values, value(check))
		}
	}
	return unique(values)
}

func collect[T any](items []T, value func(T) string) []string {
	values := make([]string, 0, len(items))
	for _, item := range items {
		values = append(values, value(item))
	}
	return values
}

func unique(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	values = values[:0]
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func profileKey(provider, complianceID string) string { return provider + "/" + complianceID }
func checkKey(provider, checkID string) string        { return provider + "/" + checkID }

func profileName(provider, complianceID string) string {
	value := strings.ToLower(provider + "-" + complianceID)
	var out strings.Builder
	dash := false
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			out.WriteRune(char)
			dash = false
		} else if !dash && out.Len() > 0 {
			out.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(out.String(), "-")
}
