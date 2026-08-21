package catalog

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

func Generate(source string) ([]byte, Manifest, error) {
	loaded, err := Load(source)
	if err != nil {
		return nil, Manifest{}, err
	}
	artifact, err := Marshal(loaded)
	if err != nil {
		return nil, Manifest{}, err
	}
	return artifact, loaded.Manifest, nil
}

func Marshal(loaded *Catalog) ([]byte, error) {
	if loaded == nil {
		return nil, fmt.Errorf("marshal prowler catalogue: catalogue is nil")
	}
	if err := loaded.finalize(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(loaded)
	if err != nil {
		return nil, fmt.Errorf("marshal prowler catalogue: %w", err)
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("compress prowler catalogue: %w", err)
	}
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("compress prowler catalogue: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("compress prowler catalogue: %w", err)
	}
	encoded := make([]byte, hex.EncodedLen(compressed.Len()))
	hex.Encode(encoded, compressed.Bytes())
	return encoded, nil
}

func Unmarshal(data []byte) (*Catalog, error) {
	compressed := make([]byte, hex.DecodedLen(len(data)))
	decoded, err := hex.Decode(compressed, data)
	if err != nil {
		return nil, fmt.Errorf("decode prowler catalogue: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed[:decoded]))
	if err != nil {
		return nil, fmt.Errorf("decompress prowler catalogue: %w", err)
	}
	uncompressed, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("decompress prowler catalogue: %w", err)
	}
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("decompress prowler catalogue: %w", err)
	}
	var loaded Catalog
	if err := json.Unmarshal(uncompressed, &loaded); err != nil {
		return nil, fmt.Errorf("unmarshal prowler catalogue: %w", err)
	}
	stored := loaded.Manifest
	if err := loaded.finalize(); err != nil {
		return nil, err
	}
	if stored != loaded.Manifest {
		return nil, fmt.Errorf("prowler catalogue manifest does not match its content")
	}
	return &loaded, nil
}

func (c *Catalog) ValidateManifest(expected Manifest) error {
	checks := []struct {
		name     string
		actual   any
		expected any
		enabled  bool
	}{
		{"version", c.Manifest.Version, expected.Version, expected.Version != ""},
		{"source commit", c.Manifest.SourceCommit, expected.SourceCommit, expected.SourceCommit != ""},
		{"providers", c.Manifest.ProviderCount, expected.ProviderCount, expected.ProviderCount != 0},
		{"static providers", c.Manifest.StaticProviderCount, expected.StaticProviderCount, expected.StaticProviderCount != 0},
		{"dynamic providers", c.Manifest.DynamicProviderCount, expected.DynamicProviderCount, expected.DynamicProviderCount != 0},
		{"checks", c.Manifest.CheckCount, expected.CheckCount, expected.CheckCount != 0},
		{"compliance files", c.Manifest.ComplianceFileCount, expected.ComplianceFileCount, expected.ComplianceFileCount != 0},
		{"profile projections", c.Manifest.ProfileProjectionCount, expected.ProfileProjectionCount, expected.ProfileProjectionCount != 0},
		{"digest", c.Manifest.Digest, expected.Digest, expected.Digest != ""},
	}
	for _, check := range checks {
		if check.enabled && check.actual != check.expected {
			return fmt.Errorf("prowler catalogue %s: got %v, want %v", check.name, check.actual, check.expected)
		}
	}
	return nil
}

func (c *Catalog) ValidatePinned() error { return c.ValidateManifest(ExpectedManifest) }

func (c *Catalog) finalize() error {
	sort.Slice(c.Providers, func(i, j int) bool { return c.Providers[i].ID < c.Providers[j].ID })
	sort.Slice(c.Checks, func(i, j int) bool { return c.Checks[i].Key < c.Checks[j].Key })
	sortProfiles(c.Profiles)

	if err := c.buildIndexes(); err != nil {
		return err
	}
	if err := c.resolveAliases(); err != nil {
		return err
	}
	if err := c.validateReferences(); err != nil {
		return err
	}
	c.refreshManifest()
	digest, err := c.contentDigest()
	if err != nil {
		return err
	}
	c.Manifest.Digest = digest
	return nil
}

func (c *Catalog) resolveAliases() error {
	aliases := map[string][]string{}
	for _, check := range c.Checks {
		for _, alias := range check.Aliases {
			aliasKey := checkKey(check.Provider, alias)
			if _, canonical := c.checksByKey[aliasKey]; canonical {
				return fmt.Errorf("prowler catalogue: check alias %s collides with a canonical check", aliasKey)
			}
			aliases[aliasKey] = append(aliases[aliasKey], check.Key)
		}
	}
	for key := range aliases {
		aliases[key] = unique(aliases[key])
	}

	resolve := func(key string) []string {
		if _, canonical := c.checksByKey[key]; canonical {
			return []string{key}
		}
		return aliases[key]
	}
	for profileIndex := range c.Profiles {
		profile := &c.Profiles[profileIndex]
		profileKeys := make([]string, 0, len(profile.CheckKeys))
		for _, key := range profile.CheckKeys {
			if canonical := resolve(key); len(canonical) > 0 {
				profileKeys = append(profileKeys, canonical...)
			} else {
				profile.MissingCheckKeys = append(profile.MissingCheckKeys, key)
			}
		}
		profile.CheckKeys = unique(profileKeys)
		profile.UnmappedControls = 0
		for controlIndex := range profile.Controls {
			control := &profile.Controls[controlIndex]
			controlKeys := make([]string, 0, len(control.CheckKeys))
			for _, key := range control.CheckKeys {
				if canonical := resolve(key); len(canonical) > 0 {
					controlKeys = append(controlKeys, canonical...)
				} else {
					control.MissingCheckKeys = append(control.MissingCheckKeys, key)
					profile.MissingCheckKeys = append(profile.MissingCheckKeys, key)
				}
			}
			control.CheckKeys = unique(controlKeys)
			control.MissingCheckKeys = unique(control.MissingCheckKeys)
			if len(control.CheckKeys) == 0 {
				profile.UnmappedControls++
			}
			configRequirements := make([]ConfigRequirement, 0, len(control.ConfigRequirements))
			for _, requirement := range control.ConfigRequirements {
				canonical := resolve(requirement.CheckKey)
				if len(canonical) == 0 {
					profile.MissingCheckKeys = append(profile.MissingCheckKeys, requirement.CheckKey)
					configRequirements = append(configRequirements, requirement)
					continue
				}
				for _, key := range canonical {
					copy := requirement
					copy.CheckKey = key
					configRequirements = append(configRequirements, copy)
				}
			}
			control.ConfigRequirements = configRequirements
		}
		profile.MissingCheckKeys = unique(profile.MissingCheckKeys)
	}
	return nil
}

func (c *Catalog) buildIndexes() error {
	c.providersByID = make(map[string]int, len(c.Providers))
	for i, provider := range c.Providers {
		if provider.ID == "" {
			return fmt.Errorf("prowler catalogue: provider ID is required")
		}
		if _, exists := c.providersByID[provider.ID]; exists {
			return fmt.Errorf("prowler catalogue: duplicate provider %q", provider.ID)
		}
		c.providersByID[provider.ID] = i
	}

	c.checksByKey = make(map[string]int, len(c.Checks))
	for i, check := range c.Checks {
		if check.Key != checkKey(check.Provider, check.ID) {
			return fmt.Errorf("prowler catalogue: check key %q does not match provider and ID", check.Key)
		}
		if _, exists := c.checksByKey[check.Key]; exists {
			return fmt.Errorf("prowler catalogue: duplicate check %q", check.Key)
		}
		c.checksByKey[check.Key] = i
	}

	c.profilesByKey = make(map[string]int, len(c.Profiles))
	profileNames := map[string]struct{}{}
	for i, profile := range c.Profiles {
		if profile.Key != profileKey(profile.Provider, profile.ComplianceID) {
			return fmt.Errorf("prowler catalogue: profile key %q does not match provider and compliance ID", profile.Key)
		}
		if _, exists := c.profilesByKey[profile.Key]; exists {
			return fmt.Errorf("prowler catalogue: duplicate profile %q", profile.Key)
		}
		if _, exists := profileNames[profile.Name]; exists {
			return fmt.Errorf("prowler catalogue: duplicate profile name %q", profile.Name)
		}
		c.profilesByKey[profile.Key] = i
		profileNames[profile.Name] = struct{}{}
	}
	return nil
}

func (c *Catalog) validateReferences() error {
	for _, check := range c.Checks {
		if _, ok := c.providersByID[check.Provider]; !ok {
			return fmt.Errorf("prowler catalogue: check %s names unknown provider %q", check.Key, check.Provider)
		}
	}
	for _, profile := range c.Profiles {
		if _, ok := c.providersByID[profile.Provider]; !ok {
			return fmt.Errorf("prowler catalogue: profile %s names unknown provider %q", profile.Key, profile.Provider)
		}
		for _, key := range profile.CheckKeys {
			if _, ok := c.checksByKey[key]; !ok {
				return fmt.Errorf("prowler catalogue: profile %s references unknown check %s", profile.Key, key)
			}
		}
		for _, control := range profile.Controls {
			for _, key := range control.CheckKeys {
				if _, ok := c.checksByKey[key]; !ok {
					return fmt.Errorf("prowler catalogue: profile %s control %s references unknown check %s", profile.Key, control.ID, key)
				}
			}
			for _, requirement := range control.ConfigRequirements {
				if _, ok := c.checksByKey[requirement.CheckKey]; !ok {
					if contains(profile.MissingCheckKeys, requirement.CheckKey) {
						continue
					}
					return fmt.Errorf("prowler catalogue: profile %s control %s config references unknown check %s", profile.Key, control.ID, requirement.CheckKey)
				}
			}
		}
	}
	return nil
}

func contains(values []string, value string) bool {
	i := sort.SearchStrings(values, value)
	return i < len(values) && values[i] == value
}

func (c *Catalog) refreshManifest() {
	for i := range c.Providers {
		c.Providers[i].CheckCount = 0
		c.Providers[i].ProfileCount = 0
		c.Providers[i].Static = false
	}
	for _, check := range c.Checks {
		i := c.providersByID[check.Provider]
		c.Providers[i].CheckCount++
		c.Providers[i].Static = true
	}
	for _, profile := range c.Profiles {
		i := c.providersByID[profile.Provider]
		c.Providers[i].ProfileCount++
	}

	static := 0
	for _, provider := range c.Providers {
		if provider.Static {
			static++
		}
	}
	c.Manifest.ProviderCount = len(c.Providers)
	c.Manifest.StaticProviderCount = static
	c.Manifest.DynamicProviderCount = len(c.Providers) - static
	c.Manifest.CheckCount = len(c.Checks)
	c.Manifest.ProfileProjectionCount = len(c.Profiles)
}

func (c *Catalog) contentDigest() (string, error) {
	digestSource := struct {
		Manifest  Manifest   `json:"manifest"`
		Providers []Provider `json:"providers"`
		Profiles  []Profile  `json:"profiles"`
		Checks    []Check    `json:"checks"`
	}{c.Manifest, c.Providers, c.Profiles, c.Checks}
	digestSource.Manifest.Digest = ""
	data, err := json.Marshal(digestSource)
	if err != nil {
		return "", fmt.Errorf("digest prowler catalogue: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
