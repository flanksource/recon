package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
	"github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

const (
	catalogArtifactPath = "internal/engines/scan/prowler/catalog/catalog.generated.json.xz"
	schemaArtifactRoot  = "internal/engines/scan/prowler/schema"
)

func buildArtifacts(argumentCatalog *arguments.Catalogue, checkCatalog *catalog.Catalog, catalogData []byte) (map[string][]byte, error) {
	if argumentCatalog == nil || checkCatalog == nil {
		return nil, fmt.Errorf("prowler argument and check catalogues are required")
	}
	normalizedArguments, err := json.Marshal(argumentCatalog)
	if err != nil {
		return nil, fmt.Errorf("encode normalized Prowler arguments: %w", err)
	}
	sourceHash := sha256.New()
	sourceHash.Write(normalizedArguments)
	sourceHash.Write([]byte("\n" + checkCatalog.Manifest.Digest))

	manifest := schema.Manifest{
		Version:                schema.ProwlerVersion,
		SourceCommit:           schema.PinnedCommit,
		ProviderCount:          len(argumentCatalog.Providers),
		ProfileProjectionCount: len(checkCatalog.Profiles),
		BuiltInProfiles:        projectBuiltInProfiles(checkCatalog),
		CommonArgumentCount:    len(argumentCatalog.Common),
		ProviderArgumentCounts: map[string]int{},
		SourceDigest:           hex.EncodeToString(sourceHash.Sum(nil)),
		CatalogDigest:          checkCatalog.Manifest.Digest,
		Digests:                map[string]string{},
	}
	artifacts := map[string][]byte{catalogArtifactPath: append([]byte(nil), catalogData...)}
	artifacts[filepath.ToSlash(filepath.Join(schemaArtifactRoot, "arguments.generated.json"))] = append(normalizedArguments, '\n')
	for _, provider := range sortedProviderArguments(argumentCatalog) {
		document, err := projectProvider(providerProjectionOptions{
			Provider: provider, Common: argumentCatalog.Common,
			CommonMutexes: argumentCatalog.CommonMutualExclusions, Checks: checkCatalog,
		})
		if err != nil {
			return nil, err
		}
		data, err := marshalGenerated(document)
		if err != nil {
			return nil, fmt.Errorf("encode Prowler %s schemas: %w", provider.Name, err)
		}
		filename := filepath.ToSlash(filepath.Join(schemaArtifactRoot, "providers", provider.Name+".generated.json"))
		artifacts[filename] = data
		manifest.Providers = append(manifest.Providers, provider.Name)
		manifest.ProviderArgumentCounts[provider.Name] = len(provider.Arguments)
		digest := sha256.Sum256(data)
		manifest.Digests[provider.Name] = hex.EncodeToString(digest[:])
	}
	if manifest.ProviderCount != len(arguments.BuiltInProviders) {
		return nil, fmt.Errorf("prowler provider schema count drift: got %d, want %d", manifest.ProviderCount, len(arguments.BuiltInProviders))
	}
	manifestData, err := marshalGenerated(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode Prowler schema manifest: %w", err)
	}
	artifacts[filepath.ToSlash(filepath.Join(schemaArtifactRoot, "manifest.generated.json"))] = manifestData
	return artifacts, nil
}

func projectBuiltInProfiles(checkCatalog *catalog.Catalog) []schema.BuiltInProfile {
	profiles := make([]schema.BuiltInProfile, 0, len(checkCatalog.Profiles))
	for _, profile := range checkCatalog.Profiles {
		profiles = append(profiles, schema.BuiltInProfile{
			Name:         profile.Name,
			Comment:      strings.TrimSpace(profile.Title + " " + profile.Version),
			Provider:     profile.Provider,
			ComplianceID: profile.ComplianceID,
		})
	}
	return profiles
}

func marshalGenerated(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func validatePortableArtifacts(repositoryRoot string, artifacts map[string][]byte) error {
	absolute := []byte(filepath.Clean(repositoryRoot))
	for filename, data := range artifacts {
		if strings.HasSuffix(filename, ".json") && bytes.Contains(data, absolute) {
			return fmt.Errorf("generated artifact %s contains repository-local path %s", filename, repositoryRoot)
		}
	}
	return nil
}

func checkArtifacts(source fs.FS, expected map[string][]byte) error {
	problems := []string{}
	for filename, want := range expected {
		got, err := fs.ReadFile(source, filename)
		if err != nil {
			if os.IsNotExist(err) {
				problems = append(problems, "missing "+filename)
				continue
			}
			return fmt.Errorf("read generated artifact %s: %w", filename, err)
		}
		if !bytes.Equal(got, want) {
			problems = append(problems, "stale "+filename)
		}
	}
	generatedFiles, err := providerArtifactFiles(source)
	if err != nil {
		return err
	}
	for _, filename := range generatedFiles {
		if _, ok := expected[filename]; !ok {
			problems = append(problems, "unexpected "+filename)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("generated Prowler artifacts drifted: %s", strings.Join(problems, "; "))
}

func providerArtifactFiles(source fs.FS) ([]string, error) {
	directory := filepath.ToSlash(filepath.Join(schemaArtifactRoot, "providers"))
	entries, err := fs.ReadDir(source, directory)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read generated Prowler provider directory: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".generated.json") {
			files = append(files, directory+"/"+entry.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

func writeArtifacts(root string, artifacts map[string][]byte) error {
	for filename, data := range artifacts {
		absolute := filepath.Join(root, filepath.FromSlash(filename))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			return fmt.Errorf("create generated artifact directory for %s: %w", filename, err)
		}
		if err := os.WriteFile(absolute, data, 0o644); err != nil {
			return fmt.Errorf("write generated artifact %s: %w", filename, err)
		}
	}
	return removeExtraProviderArtifacts(root, artifacts)
}

func removeExtraProviderArtifacts(root string, expected map[string][]byte) error {
	directory := filepath.Join(root, filepath.FromSlash(schemaArtifactRoot), "providers")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read generated Prowler provider directory: %w", err)
	}
	for _, entry := range entries {
		filename := filepath.ToSlash(filepath.Join(schemaArtifactRoot, "providers", entry.Name()))
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".generated.json") {
			continue
		}
		if _, ok := expected[filename]; ok {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return fmt.Errorf("remove stale generated artifact %s: %w", filename, err)
		}
	}
	return nil
}
