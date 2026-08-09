package all_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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
		Expect(scanNames).To(Equal([]string{"nuclei"}))
	})

	// Register panics on a malformed spec, so reaching this point already proves
	// the basics. These assertions cover what Validate cannot: that the install
	// metadata is complete enough to actually resolve a binary on this machine.
	It("declares an installable package for every engine", func() {
		for _, spec := range allSpecs() {
			By(spec.Name)
			Expect(spec.Install.Manager).To(Equal("github_release"))
			Expect(spec.Install.Repo).ToNot(BeEmpty())
			Expect(spec.Install.VersionCommand).ToNot(BeEmpty())
			Expect(spec.Install.VersionRegex).ToNot(BeEmpty())
			Expect(spec.Install.PreInstalled).To(ContainElement(spec.Binary),
				"an already-installed binary must be honoured rather than re-downloaded")

			for _, platform := range []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64"} {
				Expect(spec.Install.AssetPatterns).To(HaveKey(platform),
					"%s cannot be installed on %s", spec.Name, platform)
			}
			Expect(spec.Install.ChecksumFile).ToNot(BeEmpty(),
				"a download with no checksum is not verifiable")
		}
	})

	It("gives every engine a default profile that validates against its own catalog", func() {
		// Without an import step this is the only source of a working
		// configuration, so a default that its own catalog rejects would leave a
		// fresh install with no usable profile.
		for _, spec := range allSpecs() {
			By(spec.Name)
			Expect(spec.Defaults.Name).ToNot(BeEmpty())
			Expect(spec.Sections.Validate(spec.Defaults.Config)).To(Succeed())
		}
	})

	It("chains: every discovery engine's input is produced by an engine or the runtime", func() {
		produced := map[discovery.Kind]bool{}
		for _, engine := range discovery.All() {
			produced[engine.Emits()] = true
		}
		for _, engine := range discovery.All() {
			accepts := engine.Accepts()
			if accepts.Sourced() {
				continue // supplied by the runtime, not by a preceding engine
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

	It("always excludes the destructive template tags", func() {
		engine, err := scan.Get("nuclei")
		Expect(err).ToNot(HaveOccurred())

		// A profile must not be able to switch these back on.
		args := engine.Args(engines.Run{
			In: "hosts.txt", Out: "out.jsonl",
			Config: map[string]any{"tags": []any{"dos"}},
		})
		Expect(args).To(ContainElement("-exclude-tags"))
		Expect(args[len(args)-1]).To(Equal("dos,fuzz,bruteforce,intrusive"))
	})
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
