package trivy

import (
	"fmt"

	"github.com/flanksource/recon/internal/engines"
)

// defaultProfileName is the profile a blank database gets as the engine's own.
// Image vulnerabilities are the question trivy is most often reached for, and
// the one whose answer needs no configuration beyond a target.
const defaultProfileName = "image-vulnerabilities"

// builtInProfiles are the working configurations seeded on startup. With no
// import step this is where a usable profile comes from, so there is one per
// provider rather than one for the engine.
func builtInProfiles() (engines.DefaultProfile, []engines.DefaultProfile, error) {
	all := []engines.DefaultProfile{
		{
			Name: defaultProfileName,
			Comment: "Known vulnerabilities and embedded secrets in a container image.\n" +
				"Only what is fixable and at least medium: an image built on a stale base\n" +
				"reports hundreds of unfixed low findings that bury the ones worth acting on.\n" +
				"Read-only — the image is pulled and analysed locally.",
			Config: map[string]any{
				"provider":       ProviderImage,
				"scanners":       []any{"vuln", "secret"},
				"severity":       []any{"CRITICAL", "HIGH", "MEDIUM"},
				"pkg-types":      []any{"os", "library"},
				"ignore-unfixed": true,
				"timeout":        "10m",
			},
		},
		{
			Name: "image-full",
			Comment: "Everything trivy can find in a container image, at every severity:\n" +
				"vulnerabilities fixed or not, secrets, misconfiguration in the image's own\n" +
				"configuration, and licences. Slow and noisy by design — this is the profile\n" +
				"for investigating one image, not for sweeping an estate.",
			Config: map[string]any{
				"provider":              ProviderImage,
				"scanners":              []any{"vuln", "secret", "misconfig", "license"},
				"pkg-types":             []any{"os", "library"},
				"image-config-scanners": []any{"misconfig", "secret"},
				"license-full":          true,
				"timeout":               "30m",
			},
		},
		{
			Name: "repository-secrets",
			Comment: "Committed secrets and insecure infrastructure-as-code in a repository.\n" +
				"Deliberately not a vulnerability scan: a repository's dependency manifests\n" +
				"describe what it declares, while the image built from it describes what\n" +
				"actually ships, and the second is the one worth alerting on.",
			Config: map[string]any{
				"provider": ProviderRepository,
				"scanners": []any{"secret", "misconfig"},
				"timeout":  "10m",
			},
		},
		{
			Name: "filesystem-misconfiguration",
			Comment: "Insecure infrastructure-as-code and committed secrets in a directory on\n" +
				"this machine. The same checks as the repository profile, for a tree that is\n" +
				"already on disk rather than one to clone.",
			Config: map[string]any{
				"provider": ProviderFilesystem,
				"scanners": []any{"misconfig", "secret"},
				"timeout":  "10m",
			},
		},
	}

	var defaults engines.DefaultProfile
	rest := make([]engines.DefaultProfile, 0, len(all)-1)
	for _, profile := range all {
		if profile.Name == defaultProfileName {
			defaults = profile
			continue
		}
		rest = append(rest, profile)
	}
	if defaults.Name == "" {
		return engines.DefaultProfile{}, nil, fmt.Errorf(
			"trivy default profile %q is absent from the built-in profiles", defaultProfileName)
	}
	return defaults, rest, nil
}
