// Package trivy drives Aqua's scanner against the artifacts an estate is built
// from rather than the addresses it answers on.
//
// It is the third axis of the three scan engines. Nuclei asks what an
// unauthenticated attacker sees from the network and inspec asks whether the
// cloud account behind it is configured correctly; trivy asks what is actually
// inside the thing being served — which packages it ships, which of them have
// known vulnerabilities, and whether a secret or a bad default was baked in.
// Its subject is therefore an image, a repository or a directory, none of which
// has an address, which is why every provider here is a provider context.
//
// Credentials are deliberately ambient. Registry logins, cloud credential
// helpers and git credentials are already resolved from the environment by the
// tools trivy delegates to, and a provider context that attaches its own is
// refused by the catalog rather than silently ignored: no variant declares a
// credential schema, so ValidateCredentials rejects anything non-empty.
package trivy

import (
	"fmt"
	"maps"
	"slices"

	"github.com/flanksource/deps/pkg/types"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
)

// EngineName is the identifier used in profiles, runs and the API. It is also
// the `type` stamped on every finding, so an artifact finding is
// distinguishable from a network or compliance one without consulting the run.
const EngineName = "trivy"

// Version is the constraint deps resolves. Pinned to a minor floor rather than
// an exact release: the report schema this parses is SchemaVersion 2, which has
// been stable across the whole 0.5x–0.6x line, and pinning exactly would mean a
// patch release nobody can pick up.
const Version = ">=0.58.0"

// Engine runs trivy against one provider context at a time.
type Engine struct{ spec engines.Spec }

var _ scan.Engine = Engine{}

func init() {
	engine, err := newEngine()
	if err != nil {
		panic(fmt.Sprintf("load trivy engine: %v", err))
	}
	scan.Register(engine)
}

func newEngine() (Engine, error) {
	options, err := optionCatalog()
	if err != nil {
		return Engine{}, err
	}
	defaults, rest, err := builtInProfiles()
	if err != nil {
		return Engine{}, err
	}

	engine := Engine{spec: engines.Spec{
		Name:        EngineName,
		Subject:     engines.SubjectProviderContexts,
		Binary:      EngineName,
		Title:       "Trivy",
		Description: "Vulnerabilities, secrets, misconfiguration and licences in images, repositories and directories.",
		DocsURL:     "https://trivy.dev/latest/docs/",

		Install:         installPackage(),
		Version:         Version,
		Options:         options,
		Defaults:        defaults,
		Profiles:        rest,
		ValidateOptions: validateConfig,
	}}
	if err := engine.spec.Validate(); err != nil {
		return Engine{}, err
	}
	return engine, nil
}

func (e Engine) Spec() engines.Spec { return e.spec }

// installPackage describes the release.
//
// The asset is named rather than fetched through get.trivy.dev, which is what
// trivy's own install script and the deps default registry use. That redirector
// serves the same archive, but under a URL whose file name is not one of the
// entries in the release's published checksums file — so deps resolves it with
// no checksum at all, and the download is unverified. Naming the asset is what
// makes the sum findable.
//
// The assets are named for the version rather than the tag (0.74.0, not
// v0.74.0) and use goreleaser's word-sized architectures, so this cannot reuse
// the ProjectDiscovery helper.
func installPackage() types.Package {
	asset := func(platform string) string {
		return "trivy_{{.version}}_" + platform + ".tar.gz"
	}
	return types.Package{
		Name:    EngineName,
		Manager: "github_release",
		Repo:    "aquasecurity/trivy",
		AssetPatterns: map[string]string{
			"darwin-amd64":  asset("macOS-64bit"),
			"darwin-arm64":  asset("macOS-ARM64"),
			"linux-amd64":   asset("Linux-64bit"),
			"linux-arm64":   asset("Linux-ARM64"),
			"windows-amd64": "trivy_{{.version}}_windows-64bit.zip",
		},
		ChecksumFile: "trivy_{{.version}}_checksums.txt",

		// Honour a copy the machine already has rather than insisting on
		// managing every tool.
		PreInstalled: []string{EngineName},

		VersionCommand: "version",
		VersionRegex:   `Version:\s+v?(\d+\.\d+\.\d+)`,

		// GitHub rate limits aggressively for unauthenticated clients, and a
		// scan should not fail because the release API was briefly unavailable.
		FallbackVersion: "latest",
	}
}

// Risk is always safe.
//
// Every provider here reads: an image is pulled, a repository is cloned, a
// directory is walked, and the analysis happens locally on what came back.
// Nothing is sent to a running service and no request can disrupt what it
// examines. A provider that changed that — one that scanned a live cluster by
// deploying into it — would have to revisit this.
func (Engine) Risk(map[string]any) engines.Risk { return engines.Safe() }

// scannerOptions are the options that only mean something when a particular
// scanner is enabled.
//
// Trivy accepts and ignores them otherwise, which is the failure worth
// catching: a profile that sets ignore-unfixed without the vuln scanner reads
// as a filtered vulnerability scan and is actually not a vulnerability scan at
// all, and nothing in the results says so.
var scannerOptions = map[string][]string{
	"vuln": {
		"ignore-unfixed", "ignore-status",
		"skip-db-update", "skip-java-db-update", "db-repository",
	},
	"misconfig": {
		"misconfig-scanners", "include-non-failures",
		"checks-bundle-repository", "skip-check-update",
	},
	"license": {"license-full", "ignored-licenses"},
}

// validateConfig applies the constraints the field catalog cannot express.
func validateConfig(config map[string]any) error {
	provider, _ := config["provider"].(string)
	if _, err := find(provider); err != nil {
		return err
	}

	enabled := stringList(config["scanners"])
	for _, scanner := range slices.Sorted(maps.Keys(scannerOptions)) {
		if slices.Contains(enabled, scanner) {
			continue
		}
		for _, option := range scannerOptions[scanner] {
			if !configured(config, option) {
				continue
			}
			return fmt.Errorf(
				"%s only applies to the %s scanner, which this profile does not run: "+
					"trivy would accept it and report nothing it implies", option, scanner)
		}
	}
	return nil
}

// configured reports whether an option is set to something that changes the
// run. An explicitly false boolean and an empty list are the tool's own
// behaviour spelled out, not a request for it.
func configured(config map[string]any, key string) bool {
	value, present := config[key]
	if !present || value == nil {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed != ""
	}
	if list, ok := asList(value); ok {
		return len(list) > 0
	}
	return true
}
