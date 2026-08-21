package catalog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

var versionPattern = regexp.MustCompile(`(?m)^prowler_version\s*=\s*["']([^"']+)["']`)

func Load(root string) (*Catalog, error) {
	loaded, err := LoadFS(os.DirFS(root))
	if err != nil {
		return nil, err
	}
	if err := loaded.ValidateManifest(ExpectedManifest); err != nil {
		return nil, fmt.Errorf("prowler source at %s: %w", root, err)
	}
	return loaded, nil
}

func LoadFS(source fs.FS) (*Catalog, error) {
	version, err := loadVersion(source)
	if err != nil {
		return nil, err
	}
	loaded := &Catalog{Manifest: Manifest{Version: version, SourceCommit: PinnedCommit}}

	if err := loadProviders(source, loaded); err != nil {
		return nil, err
	}
	if err := loadCompliance(source, loaded); err != nil {
		return nil, err
	}
	if err := loaded.finalize(); err != nil {
		return nil, err
	}
	return loaded, nil
}

func GenerateFS(source fs.FS) ([]byte, Manifest, error) {
	loaded, err := LoadFS(source)
	if err != nil {
		return nil, Manifest{}, err
	}
	artifact, err := Marshal(loaded)
	if err != nil {
		return nil, Manifest{}, err
	}
	return artifact, loaded.Manifest, nil
}

func loadVersion(source fs.FS) (string, error) {
	data, err := fs.ReadFile(source, "prowler/config/config.py")
	if err != nil {
		return "", fmt.Errorf("read prowler version: %w", err)
	}
	match := versionPattern.FindSubmatch(data)
	if len(match) != 2 {
		return "", fmt.Errorf("read prowler version: prowler_version is missing")
	}
	return string(match[1]), nil
}

func loadProviders(source fs.FS, loaded *Catalog) error {
	providers := map[string]struct{}{}
	err := fs.WalkDir(source, "prowler/providers", func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}

		parts := strings.Split(filename, "/")
		if len(parts) == 4 && parts[0] == "prowler" && parts[1] == "providers" &&
			parts[2] != "common" && parts[3] == parts[2]+"_provider.py" {
			providers[parts[2]] = struct{}{}
		}
		if !strings.HasSuffix(filename, ".metadata.json") {
			return nil
		}
		check, err := parseCheck(source, filename)
		if err != nil {
			return err
		}
		loaded.Checks = append(loaded.Checks, check)
		return nil
	})
	if err != nil {
		return fmt.Errorf("load prowler providers: %w", err)
	}

	for provider := range providers {
		loaded.Providers = append(loaded.Providers, Provider{ID: provider})
	}
	if len(loaded.Providers) == 0 {
		return fmt.Errorf("load prowler providers: no built-in providers found")
	}
	return nil
}

type checkSource struct {
	Provider           string            `json:"Provider"`
	CheckID            string            `json:"CheckID"`
	CheckTitle         string            `json:"CheckTitle"`
	CheckAliases       []string          `json:"CheckAliases"`
	CheckType          []string          `json:"CheckType"`
	ServiceName        string            `json:"ServiceName"`
	SubServiceName     string            `json:"SubServiceName"`
	ResourceIDTemplate string            `json:"ResourceIdTemplate"`
	Severity           string            `json:"Severity"`
	ResourceType       string            `json:"ResourceType"`
	ResourceGroup      string            `json:"ResourceGroup"`
	Description        string            `json:"Description"`
	Risk               string            `json:"Risk"`
	RelatedURL         string            `json:"RelatedUrl"`
	AdditionalURLs     []string          `json:"AdditionalURLs"`
	Remediation        remediationSource `json:"Remediation"`
	Categories         []string          `json:"Categories"`
	DependsOn          []string          `json:"DependsOn"`
	RelatedTo          []string          `json:"RelatedTo"`
	Notes              string            `json:"Notes"`
}

type remediationSource struct {
	Code           map[string]string `json:"Code"`
	Recommendation struct {
		Text string `json:"Text"`
		URL  string `json:"Url"`
	} `json:"Recommendation"`
}

func parseCheck(source fs.FS, filename string) (Check, error) {
	data, err := fs.ReadFile(source, filename)
	if err != nil {
		return Check{}, fmt.Errorf("read check %s: %w", filename, err)
	}
	var input checkSource
	if err := json.Unmarshal(data, &input); err != nil {
		return Check{}, fmt.Errorf("parse check %s: %w", filename, err)
	}
	input.Provider = strings.ToLower(input.Provider)
	if err := validateCheckSource(filename, input); err != nil {
		return Check{}, err
	}

	code := map[string]string{}
	for key, value := range input.Remediation.Code {
		if key == "" {
			return Check{}, fmt.Errorf("parse check %s: remediation code key is empty", filename)
		}
		code[lowerInitialism(key)] = value
	}
	references := append([]string{}, input.AdditionalURLs...)
	if input.RelatedURL != "" {
		references = append(references, input.RelatedURL)
	}
	if input.Remediation.Recommendation.URL != "" {
		references = append(references, input.Remediation.Recommendation.URL)
	}

	return Check{
		Key:                checkKey(input.Provider, input.CheckID),
		ID:                 input.CheckID,
		Provider:           input.Provider,
		Title:              input.CheckTitle,
		Aliases:            unique(input.CheckAliases),
		Severity:           strings.ToLower(input.Severity),
		Service:            input.ServiceName,
		SubService:         input.SubServiceName,
		CheckTypes:         unique(input.CheckType),
		ResourceType:       input.ResourceType,
		ResourceGroup:      input.ResourceGroup,
		ResourceIDTemplate: input.ResourceIDTemplate,
		Categories:         unique(input.Categories),
		Description:        input.Description,
		Risk:               input.Risk,
		Remediation: Remediation{
			Text: input.Remediation.Recommendation.Text,
			URL:  input.Remediation.Recommendation.URL,
			Code: code,
		},
		References: unique(references),
		DependsOn:  qualify(input.Provider, input.DependsOn),
		RelatedTo:  qualify(input.Provider, input.RelatedTo),
		Notes:      input.Notes,
		Source:     filename,
	}, nil
}

func validateCheckSource(filename string, check checkSource) error {
	parts := strings.Split(filename, "/")
	if len(parts) < 7 || parts[0] != "prowler" || parts[1] != "providers" {
		return fmt.Errorf("check metadata has unexpected path %s", filename)
	}
	pathProvider := parts[2]
	checkDir := parts[len(parts)-2]
	fileID := strings.TrimSuffix(parts[len(parts)-1], ".metadata.json")
	if check.Provider == "" || check.CheckID == "" || check.CheckTitle == "" || check.ServiceName == "" || check.ResourceType == "" {
		return fmt.Errorf("check %s: Provider, CheckID, CheckTitle, ServiceName, and ResourceType are required", filename)
	}
	if check.Provider != pathProvider || check.CheckID != checkDir || check.CheckID != fileID {
		return fmt.Errorf("check %s: provider/check ID does not match its path", filename)
	}
	switch strings.ToLower(check.Severity) {
	case "critical", "high", "medium", "low", "informational":
	default:
		return fmt.Errorf("check %s: unknown severity %q", filename, check.Severity)
	}
	return nil
}

func loadCompliance(source fs.FS, loaded *Catalog) error {
	err := fs.WalkDir(source, "prowler/compliance", func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || path.Ext(filename) != ".json" {
			return nil
		}
		data, err := fs.ReadFile(source, filename)
		if err != nil {
			return fmt.Errorf("read compliance %s: %w", filename, err)
		}
		var shape map[string]json.RawMessage
		if err := json.Unmarshal(data, &shape); err != nil {
			return fmt.Errorf("parse compliance %s: %w", filename, err)
		}
		var profiles []Profile
		switch {
		case shape["Requirements"] != nil:
			profiles, err = parseProviderCompliance(filename, data)
		case shape["requirements"] != nil:
			profiles, err = parseSharedCompliance(filename, data)
		default:
			err = fmt.Errorf("parse compliance %s: unknown compliance schema", filename)
		}
		if err != nil {
			return err
		}
		loaded.Manifest.ComplianceFileCount++
		loaded.Profiles = append(loaded.Profiles, profiles...)
		return nil
	})
	if err != nil {
		return fmt.Errorf("load prowler compliance: %w", err)
	}
	return nil
}

func qualify(provider string, ids []string) []string {
	keys := make([]string, 0, len(ids))
	for _, id := range ids {
		keys = append(keys, checkKey(provider, id))
	}
	return unique(keys)
}

func lowerInitialism(value string) string {
	switch value {
	case "CLI":
		return "cli"
	case "NativeIaC":
		return "nativeIaC"
	default:
		return strings.ToLower(value[:1]) + value[1:]
	}
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
