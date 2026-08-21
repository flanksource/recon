// Package inspec drives CINC Auditor — the license-free build of Chef InSpec —
// against cloud accounts.
//
// This is the inside-out counterpart to nuclei. Nuclei asks what an
// unauthenticated attacker can see from the network; InSpec asks whether the
// account behind it is configured correctly, by reading the provider's own APIs
// with credentials. Its subject is therefore an account rather than an endpoint,
// and it is the reason engines.SubjectAccounts exists.
package inspec

import (
	"fmt"
	"strings"

	"github.com/flanksource/deps/pkg/types"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
)

// EngineName is the identifier used in profiles, runs and the API. It is also
// the `type` stamped on every finding, so a compliance result is
// distinguishable from a network one without consulting the run.
const EngineName = "inspec"

// Engine runs InSpec profiles.
type Engine struct{}

var _ scan.Engine = Engine{}

func init() { scan.Register(Engine{}) }

// GCPCISProfile is the benchmark seeded on a blank database.
//
// Pinned to a commit rather than a tag: the repository's newest release is
// v1.1.0-28 from July 2021, while master carries the CIS 4.0 profile and is
// still maintained. A tag would pin a benchmark four major versions out of date.
const GCPCISProfile = "https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark/" +
	"archive/cc455029df7b89f07ab1736cadd82337062d01e0.tar.gz"

// cincAuditor is the deps package that provisions the runner.
//
// CINC rather than Chef InSpec: same source, same profiles, Apache-2.0 with no
// EULA, where Chef's own binaries need a paid licence for commercial use.
//
// It carries no asset patterns because Omnitruck resolves the artifact and its
// checksum from a platform triple, and no install mode because what it resolves
// to is an operating-system package — an omnibus build links /opt/cinc-auditor
// into its interpreter's dylib paths and its $LOAD_PATH, so a copy unpacked
// anywhere else cannot run.
func cincAuditor() types.Package {
	return types.Package{
		Name:    "cinc-auditor",
		Manager: "omnitruck",
		Extra: map[string]any{
			"channel":  "stable",
			"product":  "cinc-auditor",
			"base_url": "https://omnitruck.cinc.sh",
		},
		// Honour a copy the machine already has, under either name: `inspec` is
		// the symlink CINC's own postinstall creates, and Chef's InSpec installs
		// under that name too.
		PreInstalled:   []string{"cinc-auditor", "inspec"},
		VersionCommand: "version",
		VersionRegex:   `(\d+\.\d+\.\d+)`,
	}
}

// Spec describes the InSpec runner.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:        EngineName,
		Binary:      "cinc-auditor",
		Title:       "InSpec",
		Description: "Credentialed compliance benchmarks (CIS) against cloud accounts.",
		DocsURL:     "https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark",

		// The subject is a GCP project, not an address. Everything else about a
		// run — the selector, the risk gate, the artifact directory — is the
		// same as any other scan.
		Subject: engines.SubjectAccounts,

		Install: cincAuditor(),
		Version: ">=7.0.0",
		Options: engines.OptionsFromSections(catalog),

		ValidateOptions: validateConfig,

		Defaults: engines.DefaultProfile{
			Name: "gcp-cis",
			Comment: "CIS Google Cloud Platform Foundation Benchmark v4.0.\n" +
				"Read-only: every control is a Google API read, so this is safe to\n" +
				"run against a production project. Needs Application Default\n" +
				"Credentials with at least Viewer and Security Reviewer on the\n" +
				"project being audited.",
			Config: map[string]any{
				"profile": GCPCISProfile,
				// The benchmark's own defaults, restated so they are visible and
				// editable in the profile form rather than hidden in the Ruby.
				"sa-key-older-than-seconds":   7776000,
				"kms-rotation-period-seconds": 7776000,
			},
		},
	}
}

// Risk is always safe.
//
// The engine judges and the runtime gates, so this has to be stated rather than
// assumed: every control in a cloud benchmark is a read against the provider's
// management API. Nothing is sent to the workloads themselves, and no request
// can disrupt what it audits. A profile that could change that — one that ran
// against ssh:// and executed commands on a host — would have to revisit this.
func (Engine) Risk(map[string]any) engines.Risk { return engines.Safe() }

// catalog is the option surface a profile may set.
var catalog = engines.Sections{
	{
		ID:          "profile",
		Title:       "Benchmark",
		Description: "Which profile to run and which of its controls.",
		SourceURL:   "https://docs.chef.io/inspec/cli/",
		Properties: []engines.Field{
			engines.Str("profile", "Profile",
				"The InSpec profile to run: a URL, a git reference, or a local path. "+
					"Pin a URL to a tag or commit — an unpinned profile makes a run unreproducible."),
			engines.StrList("controls", "Controls",
				"Run only these control IDs. Empty runs the whole benchmark."),
		},
	},
	{
		ID:          "inputs",
		Title:       "Inputs",
		Description: "The benchmark's own thresholds. Each becomes an InSpec input.",
		SourceURL:   "https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark#inputs",
		Properties: []engines.Field{
			engines.Int("sa-key-older-than-seconds", "Service account key age",
				"Fail a service-account key older than this many seconds. The CIS default is 90 days.", 1),
			engines.Int("kms-rotation-period-seconds", "KMS rotation period",
				"Fail a KMS key not rotated within this many seconds. The CIS default is 90 days.", 1),
			engines.Str("cis-version", "CIS version",
				"The benchmark version recorded on each control's tags."),
			engines.StrList("gce-zones", "Compute zones",
				"Zones to search for Compute instances. Empty searches every zone, which is slower."),
			engines.StrList("gcp-gke-locations", "GKE locations",
				"Regions and zones to search for GKE clusters. Empty searches every location."),
		},
	},
	{
		ID:          "execution",
		Title:       "Execution",
		Description: "How the run is bounded.",
		SourceURL:   "https://docs.chef.io/inspec/cli/",
		Properties: []engines.Field{
			engines.Int("max-time", "Time limit",
				"Seconds before the run is cancelled. A full benchmark makes thousands of API calls.", 1),
		},
	},
}

// inputKeys are the catalog options that become InSpec inputs rather than
// flags, mapped to the input name the profile declares.
//
// An explicit table rather than a naming convention: the profile's input names
// are its contract, and a convention would silently pass an input the benchmark
// ignores if either side renamed anything.
var inputKeys = map[string]string{
	"sa-key-older-than-seconds":   "sa_key_older_than_seconds",
	"kms-rotation-period-seconds": "kms_rotation_period_seconds",
	"cis-version":                 "cis_version",
	"gce-zones":                   "gce_zones",
	"gcp-gke-locations":           "gcp_gke_locations",
}

// validateConfig applies the constraints the field catalog cannot express.
func validateConfig(config map[string]any) error {
	profile, _ := config["profile"].(string)
	if strings.TrimSpace(profile) == "" {
		return fmt.Errorf("profile is required: there is no default benchmark to run")
	}

	// A profile URL that names a branch resolves to different controls on
	// different days, so a run against it cannot be reproduced or compared.
	if isURL(profile) && namesBranch(profile) {
		return fmt.Errorf(
			"profile %q points at a branch: pin a tag or commit, or a re-run will not "+
				"be comparable to this one", profile)
	}
	return nil
}

func isURL(profile string) bool {
	return strings.HasPrefix(profile, "http://") || strings.HasPrefix(profile, "https://")
}

// mutableRefs are the git references whose contents change under them.
var mutableRefs = []string{"/main.tar.gz", "/master.tar.gz", "/HEAD.tar.gz", "/heads/main", "/heads/master"}

func namesBranch(profile string) bool {
	for _, ref := range mutableRefs {
		if strings.HasSuffix(profile, ref) || strings.Contains(profile, ref) {
			return true
		}
	}
	return false
}
