package engines

import (
	"fmt"

	"github.com/flanksource/deps/pkg/types"
)

// ProjectDiscovery builds the deps package for a ProjectDiscovery tool.
//
// They all ship goreleaser archives from GitHub releases with the same asset
// naming — `<tool>_<version>_macOS_arm64.zip`, note "macOS" rather than
// "darwin" — so the pattern is generated rather than repeated seven times.
//
// The release is tagged "v1.7.0" but its assets are named "1.7.0", so these use
// {{.version}} — the tag with any leading "v" stripped — and not {{.tag}}, which
// keeps it.
func ProjectDiscovery(tool string) types.Package {
	return types.Package{
		Name:    tool,
		Manager: "github_release",
		Repo:    "projectdiscovery/" + tool,
		AssetPatterns: map[string]string{
			"darwin-amd64":  fmt.Sprintf("%s_{{.version}}_macOS_amd64.zip", tool),
			"darwin-arm64":  fmt.Sprintf("%s_{{.version}}_macOS_arm64.zip", tool),
			"linux-amd64":   fmt.Sprintf("%s_{{.version}}_linux_amd64.zip", tool),
			"linux-arm64":   fmt.Sprintf("%s_{{.version}}_linux_arm64.zip", tool),
			"windows-amd64": fmt.Sprintf("%s_{{.version}}_windows_amd64.zip", tool),
		},
		ChecksumFile: fmt.Sprintf("%s_{{.version}}_checksums.txt", tool),

		// Honour a copy the machine already has rather than insisting on
		// managing every tool.
		PreInstalled: []string{tool},

		// Every ProjectDiscovery tool prints "Current Version: x.y.z" to stderr
		// under -version.
		VersionCommand: "-version",
		VersionRegex:   `v?(\d+\.\d+\.\d+)`,

		// GitHub rate limits aggressively for unauthenticated clients, and a
		// scan should not fail because the release API was briefly unavailable.
		FallbackVersion: "latest",
	}
}

// WithChecksumFile overrides the checksum file pattern. Most ProjectDiscovery
// tools publish `<tool>_<version>_checksums.txt`, but katana hyphenates it and
// naabu omits the version entirely.
func WithChecksumFile(pkg types.Package, pattern string) types.Package {
	pkg.ChecksumFile = pattern
	return pkg
}
