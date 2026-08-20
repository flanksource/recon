package all_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	// Imported for its init, which registers every manager: the roster this
	// checks engine specs against is only populated once they have registered.
	_ "github.com/flanksource/deps/pkg/installer"
	depsmanager "github.com/flanksource/deps/pkg/manager"

	"github.com/flanksource/recon/internal/engines"
	_ "github.com/flanksource/recon/internal/engines/all"
	"github.com/flanksource/recon/internal/engines/discovery"
	"github.com/flanksource/recon/internal/engines/scan"
)

func TestEngines(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "engines")
}

func repoRoot() string {
	dir, err := os.Getwd()
	Expect(err).ToNot(HaveOccurred())
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		Expect(parent).ToNot(Equal(dir))
		dir = parent
	}
}

// allSpecs is every registered engine, whichever registry it came from.
func allSpecs() []engines.Spec {
	return append(discovery.Specs(), scan.Specs()...)
}

var _ = Describe("the engine registries", func() {
	It("registers the expected engines", func() {
		var discoveryNames []string
		for _, spec := range discovery.Specs() {
			discoveryNames = append(discoveryNames, spec.Name)
		}
		Expect(discoveryNames).To(Equal([]string{
			"dnsx", "httpx", "katana", "naabu", "subfinder", "tlsx",
		}))

		var scanNames []string
		for _, spec := range scan.Specs() {
			scanNames = append(scanNames, spec.Name)
		}
		Expect(scanNames).To(Equal([]string{"inspec", "nuclei"}))
	})

	// Register panics on a malformed spec, so reaching this point already proves
	// the basics. These assertions cover what Validate cannot: that the install
	// metadata is complete enough to actually resolve a binary on this machine.
	It("declares an installable package for every engine that is a binary", func() {
		for _, spec := range allSpecs() {
			if spec.InProcess {
				// Nothing to provision, and nothing that could be missing. The
				// artifact a linked-in engine still needs is its templates,
				// which the runtime installs rather than deps.
				By(spec.Name + " (in-process)")
				Expect(spec.Install.Name).To(BeEmpty(),
					"install metadata for an engine that is never installed")
				continue
			}

			By(spec.Name)
			Expect(depsmanager.GetGlobalRegistry().List()).To(ContainElement(spec.Install.Manager),
				"%s names a manager deps does not have", spec.Name)
			Expect(spec.Install.VersionCommand).ToNot(BeEmpty())
			Expect(spec.Install.VersionRegex).ToNot(BeEmpty())
			Expect(spec.Install.PreInstalled).To(ContainElement(spec.Binary),
				"an already-installed binary must be honoured rather than re-downloaded")

			// Asset patterns and a checksum file are how a github_release
			// package names its artifact. A manager that resolves the artifact
			// and its checksum from an API — omnitruck does — has neither, and
			// requiring them would be requiring metadata nothing reads.
			if spec.Install.Manager != "github_release" {
				continue
			}

			Expect(spec.Install.Repo).ToNot(BeEmpty())
			for _, platform := range []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64"} {
				Expect(spec.Install.AssetPatterns).To(HaveKey(platform),
					"%s cannot be installed on %s", spec.Name, platform)
			}
			Expect(spec.Install.ChecksumFile).ToNot(BeEmpty(),
				"a download with no checksum is not verifiable")
		}
	})

	It("verifies every download, whichever manager resolves it", func() {
		// The github_release packages name a checksum file; omnitruck returns
		// the checksum with the URL. Either way an unverified download must not
		// be possible, so this states the requirement once rather than leaving
		// it implied by each manager's own metadata.
		for _, spec := range allSpecs() {
			if spec.InProcess {
				continue
			}
			By(spec.Name)
			switch spec.Install.Manager {
			case "github_release":
				Expect(spec.Install.ChecksumFile).ToNot(BeEmpty())
			case "omnitruck":
				// Omnitruck's metadata endpoint returns sha256 alongside the
				// URL, and the manager refuses a response without one.
			default:
				Fail("no checksum story for manager " + spec.Install.Manager)
			}
		}
	})

	It("gives every engine built-in profiles that validate against its own catalog", func() {
		// Without an import step this is the only source of a working
		// configuration, so a profile that its own catalog rejects would leave a
		// fresh install with no usable profile.
		for _, spec := range allSpecs() {
			By(spec.Name)
			Expect(spec.Defaults.Name).ToNot(BeEmpty())
			for _, profile := range spec.BuiltInProfiles() {
				Expect(spec.ValidateConfig(profile.Config)).To(Succeed())
			}
		}
	})

	It("publishes the Nuclei scan profiles written here", func() {
		// The imported community profiles are not listed: they come from the
		// installed templates release and change with it, so pinning them here
		// would make a template update a test failure. That they are present,
		// valid and non-empty is covered in the nuclei package itself.
		var names []string
		for _, profile := range mustFind("nuclei").BuiltInProfiles() {
			names = append(names, profile.Name)
		}

		Expect(names).To(ContainElements(
			"safe", "full",
			"static", "dns", "java", "go", "k8s", "public", "app",
		))
	})

	It("gives every scan profile a name the database will accept", func() {
		// engine_profiles has a check constraint on the name format, and a
		// built-in profile that violates it fails at seeding — on startup, for
		// everyone, rather than for whoever created it.
		valid := regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

		for _, spec := range allSpecs() {
			for _, profile := range spec.BuiltInProfiles() {
				Expect(profile.Name).To(MatchRegexp(valid.String()),
					"%s profile %q cannot be stored", spec.Name, profile.Name)
			}
		}
	})

	It("chains: every discovery engine's input can be supplied by something", func() {
		// A stage is fed by an earlier engine, by the inventory, or by whatever
		// seeds the chain. Zones and hosts are the two seeds the runner supports:
		// a full sweep starts from the configured zones, a targeted one from the
		// hosts it was handed.
		seeds := map[discovery.Kind]bool{discovery.Zones: true, discovery.Hosts: true}

		produced := map[discovery.Kind]bool{}
		for _, engine := range discovery.All() {
			produced[engine.Emits()] = true
		}
		for _, engine := range discovery.All() {
			accepts := engine.Accepts()
			if accepts.Sourced() || seeds[accepts] {
				continue
			}
			Expect(produced).To(HaveKey(accepts),
				"%s consumes %s, which nothing produces", engine.Spec().Name, accepts)
		}
	})

	It("has an engine for every kind the runtime does not source itself", func() {
		// The mirror of the assertion above: a kind that is neither sourced nor
		// consumed by anything means a stage produces output nothing can use.
		consumed := map[discovery.Kind]bool{discovery.Observations: true} // the terminal kind
		for _, engine := range discovery.All() {
			consumed[engine.Accepts()] = true
		}
		for _, engine := range discovery.All() {
			Expect(consumed).To(HaveKey(engine.Emits()),
				"%s emits %s, which nothing consumes", engine.Spec().Name, engine.Emits())
		}
	})
})

// The catalogs are generated from the TypeScript originals. This asserts the
// generated Go still reproduces them exactly — which is what makes the codegen
// trustworthy rather than a one-time transcription nobody can verify.
var _ = Describe("the generated option catalogs", func() {
	It("match the catalog they were generated from", func() {
		raw, err := os.ReadFile(filepath.Join(repoRoot(), "internal/engines/testdata/catalog.json"))
		Expect(err).ToNot(HaveOccurred())

		var expected map[string]json.RawMessage
		Expect(json.Unmarshal(raw, &expected)).To(Succeed())

		byName := map[string]engines.Spec{}
		for _, spec := range allSpecs() {
			byName[spec.Name] = spec
		}

		for name, want := range expected {
			spec, ok := byName[name]
			Expect(ok).To(BeTrue(), "no engine registered for catalog %s", name)

			got, err := json.Marshal(spec.Sections)
			Expect(err).ToNot(HaveOccurred())
			Expect(got).To(MatchJSON(want), "catalog for %s drifted from the source", name)
		}
	})

	It("preserves option order, which is the form layout", func() {
		// A map would randomise this and encoding/json would sort it
		// alphabetically; either scrambles a form whose grouping is deliberate.
		spec := mustFind("naabu")
		Expect(spec.Sections[0].Properties[0].Key).To(Equal("port"))
		Expect(spec.Sections[0].Properties[1].Key).To(Equal("top-ports"))

		encoded, err := json.Marshal(spec.Sections[0])
		Expect(err).ToNot(HaveOccurred())
		Expect(string(encoded)).To(MatchRegexp(`"properties":\{"port":.*"top-ports":`))
	})
})

var _ = Describe("profile validation", func() {
	It("rejects an unknown option", func() {
		err := mustFind("naabu").Sections.Validate(map[string]any{"nope": 1})
		Expect(err).To(MatchError(ContainSubstring("unsupported option: nope")))
	})

	It("rejects a value outside an enum", func() {
		err := mustFind("naabu").Sections.Validate(map[string]any{"top-ports": "9999"})
		Expect(err).To(MatchError(ContainSubstring("expected one of")))
	})

	It("rejects a value below a minimum", func() {
		err := mustFind("naabu").Sections.Validate(map[string]any{"rate": 0})
		Expect(err).To(MatchError(ContainSubstring("minimum")))
	})

	It("rejects a wrongly typed value", func() {
		err := mustFind("naabu").Sections.Validate(map[string]any{"exclude-cdn": "yes"})
		Expect(err).To(MatchError(ContainSubstring("expected boolean")))
	})

	It("accepts a float with no fractional part where an integer is required", func() {
		// YAML decodes 250 as an int and JSON as a float64; both have to work.
		Expect(mustFind("naabu").Sections.Validate(map[string]any{"rate": float64(250)})).To(Succeed())
	})

	It("reports every problem at once rather than the first", func() {
		err := mustFind("naabu").Sections.Validate(map[string]any{"nope": 1, "alsonope": 2})
		Expect(err).To(MatchError(ContainSubstring("alsonope")))
		Expect(err).To(MatchError(ContainSubstring("nope")))
	})
})

var _ = Describe("command lines", func() {
	It("renders booleans as bare flags and omits false ones", func() {
		args := engines.ConfigArgs(map[string]any{"exclude-cdn": true, "display-cdn": false})
		Expect(args).To(Equal([]string{"-exclude-cdn"}))
	})

	It("renders numbers without a decimal point", func() {
		Expect(engines.ConfigArgs(map[string]any{"rate": float64(250)})).
			To(Equal([]string{"-rate", "250"}))
	})

	It("repeats a flag for each element of a list", func() {
		Expect(engines.ConfigArgs(map[string]any{"severity": []any{"high", "critical"}})).
			To(Equal([]string{"-severity", "high", "-severity", "critical"}))
	})

	It("orders flags deterministically so a recorded command is diffable", func() {
		config := map[string]any{"zeta": "1", "alpha": "2", "mid": "3"}
		Expect(engines.ConfigArgs(config)).
			To(Equal([]string{"-alpha", "2", "-mid", "3", "-zeta", "1"}))
	})
})

var _ = Describe("the nuclei scan engine", func() {
	It("treats DAST as intrusive and everything else as safe", func() {
		engine, err := scan.Get("nuclei")
		Expect(err).ToNot(HaveOccurred())

		Expect(engine.Risk(map[string]any{}).Intrusive).To(BeFalse())
		Expect(engine.Risk(map[string]any{"dast": false}).Intrusive).To(BeFalse())

		risk := engine.Risk(map[string]any{"dast": true})
		Expect(risk.Intrusive).To(BeTrue())
		Expect(risk.Reason).To(ContainSubstring("fuzzing"))
	})

	// Nuclei's refusal to run destructive templates whatever a profile says is
	// asserted where it is now enforced — against the options the engine
	// actually reads, in internal/engines/scan/nuclei/options_test.go. It used
	// to be checked here, on the last two arguments of a command line that no
	// longer exists.
})

func mustFind(name string) engines.Spec {
	for _, spec := range allSpecs() {
		if spec.Name == name {
			return spec
		}
	}
	Fail("engine not registered: " + name)
	return engines.Spec{}
}
