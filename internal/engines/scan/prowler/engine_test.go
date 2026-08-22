package prowler

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
	"github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

var _ = Describe("the Prowler engine", func() {
	var engine Engine

	BeforeEach(func() {
		loaded, err := newEngine()
		Expect(err).ToNot(HaveOccurred())
		engine = loaded
	})

	It("registers the pinned PATH-only runtime and every generated provider", func() {
		spec := engine.Spec()
		Expect(spec.Validate()).To(Succeed())
		Expect(spec.Name).To(Equal(EngineName))
		Expect(spec.Subject).To(Equal(engines.SubjectProviderContexts))
		Expect(spec.Provisioning).To(Equal(engines.ProvisioningPathOnly))
		Expect(spec.Version).To(Equal(schema.ProwlerVersion))
		Expect(spec.Install.VersionCommand).To(Equal("--version"))
		Expect(spec.Install.VersionRegex).To(Equal(`(?i)prowler(?:\s+version)?\s+v?(\d+\.\d+\.\d+)`))
		Expect(spec.Options.Discriminator).To(Equal("provider"))
		Expect(spec.Options.Variants).To(HaveLen(catalog.ExpectedManifest.ProviderCount))
		corpus := engine.Corpus()
		Expect(corpus.ItemLabel).To(Equal("check"))
		Expect(corpus.ProfileLabel).To(Equal("compliance framework"))
	})

	It("does not load catalogue metadata for the spec or corpus summary", func() {
		loads := 0
		lazy := Engine{
			arguments: engine.arguments,
			spec:      engine.spec,
			catalogue: func() (*catalog.Catalog, error) {
				loads++
				return catalog.Embedded()
			},
		}

		Expect(lazy.Spec().Name).To(Equal(EngineName))
		Expect(lazy.Corpus().Count).To(Equal(catalog.ExpectedManifest.CheckCount))
		Expect(loads).To(BeZero())
		_, err := lazy.Templates()
		Expect(err).NotTo(HaveOccurred())
		Expect(loads).To(Equal(1))
	})

	It("adapts every generated compliance profile with GCP CIS 5.0 as the default", func() {
		profiles := engine.Spec().BuiltInProfiles()
		Expect(profiles).To(HaveLen(catalog.ExpectedManifest.ProfileProjectionCount))
		Expect(engine.Spec().Defaults).To(Equal(engines.DefaultProfile{
			Name:    "gcp-cis-5-0-gcp",
			Comment: "CIS Google Cloud Platform Foundation Benchmark v5.0.0 5.0",
			Config: map[string]any{
				"provider": "gcp", "compliance": []any{"cis_5.0_gcp"},
			},
		}))
		for _, profile := range profiles {
			provider, ok := profile.Config["provider"].(string)
			Expect(ok).To(BeTrue(), profile.Name)
			Expect(provider).ToNot(BeEmpty(), profile.Name)
			Expect(engine.Spec().ValidateConfig(profile.Config)).To(Succeed(), profile.Name)
		}
	})

	It("rejects invalid output and mutually exclusive selections before execution", func() {
		Expect(engine.Spec().ValidateConfig(map[string]any{
			"provider": "gcp", "output-formats": []any{"csv", "html"},
		})).To(MatchError(ContainSubstring("must include json-ocsf")))
		Expect(engine.Spec().ValidateConfig(map[string]any{
			"provider": "gcp", "compliance": []any{"cis_5.0_gcp"},
			"checks": []any{"apikeys_key_exists"},
		})).To(MatchError(ContainSubstring("accepts only one argument")))
	})

	It("selects individual checks without assuming a compliance framework", func() {
		selected, err := engine.Select(map[string]any{
			"provider": "gcp", "checks": []any{"apikeys_key_exists"},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(selected).To(ConsistOf(HaveField("ID", "gcp/apikeys_key_exists")))
	})

	// The profile schema names this option `severities`; `severity` is only
	// Prowler's argparse destination. Reading the destination matched nothing,
	// so a filtered profile previewed as though it ran the whole service.
	It("narrows a selection by the severities the profile asked for", func() {
		service := map[string]any{"provider": "gcp", "services": []any{"apikeys"}}

		all, err := engine.Select(service)
		Expect(err).ToNot(HaveOccurred())
		Expect(all).ToNot(BeEmpty())

		wanted := strings.ToLower(all[0].Severity)
		expected := 0
		for _, check := range all {
			if strings.EqualFold(check.Severity, wanted) {
				expected++
			}
		}
		Expect(expected).To(BeNumerically("<", len(all)),
			"the fixture needs a service carrying more than one severity")

		filtered, err := engine.Select(map[string]any{
			"provider": "gcp", "services": []any{"apikeys"}, "severities": []any{wanted},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(filtered).To(HaveLen(expected))
	})
})
