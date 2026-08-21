package trivy

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
)

func spec() engines.Spec {
	GinkgoHelper()
	engine, err := newEngine()
	Expect(err).ToNot(HaveOccurred())
	return engine.Spec()
}

var _ = Describe("the trivy option catalog", func() {
	It("offers one variant per provider, selected by the provider field", func() {
		catalog := spec().Options

		Expect(catalog.Discriminator).To(Equal("provider"))
		ids := []string{}
		for _, variant := range catalog.Variants {
			ids = append(ids, variant.ID)
		}
		Expect(ids).To(Equal([]string{ProviderImage, ProviderRepository, ProviderFilesystem}))
	})

	It("gives every provider a context schema, which is what makes it selectable as a target", func() {
		// The Add Target dialog lists exactly the providers some scan engine
		// declares context options for. A variant without one is a provider
		// nothing can create a target for.
		for _, variant := range spec().Options.Variants {
			By(variant.ID)
			Expect(variant.ContextSchema).ToNot(BeNil())
		}
	})

	It("declares no credentials, because trivy reads them from its environment", func() {
		for _, variant := range spec().Options.Variants {
			By(variant.ID)
			Expect(variant.CredentialSchema).To(BeNil())
			// A context that attaches credentials anyway is refused rather than
			// scanned unauthenticated.
			Expect(spec().Options.ValidateCredentials(
				map[string]any{"provider": variant.ID},
				map[string]any{"envVars": []any{map[string]any{"name": "TRIVY_PASSWORD", "value": "x"}}},
			)).To(MatchError(ContainSubstring("does not accept credentials")))
		}
	})

	It("requires the provider to say what it is scanning", func() {
		for _, entry := range providers {
			By(entry.ID)
			err := spec().ValidateContext(map[string]any{"provider": entry.ID}, map[string]any{})
			Expect(err).To(MatchError(ContainSubstring(entry.Subject)))
		}
	})

	It("refuses an empty subject, which would scan nothing and report a clean run", func() {
		err := spec().ValidateContext(
			map[string]any{"provider": ProviderImage}, map[string]any{"image": ""})
		Expect(err).To(HaveOccurred())
	})

	It("refuses a relative filesystem path when the target is saved, not when it runs", func() {
		config := map[string]any{"provider": ProviderFilesystem}

		Expect(spec().ValidateContext(config, map[string]any{"path": "src"})).To(HaveOccurred())
		Expect(spec().ValidateContext(config, map[string]any{"path": "/srv/checkout"})).To(Succeed())
	})

	It("refuses a context option written for a different provider", func() {
		// branch belongs to a repository, and silently ignoring it on an image
		// would leave someone believing they had pinned a revision.
		err := spec().ValidateContext(
			map[string]any{"provider": ProviderImage},
			map[string]any{"image": "alpine:3.19", "branch": "main"})
		Expect(err).To(MatchError(ContainSubstring("branch")))
	})
})

var _ = Describe("validating a trivy profile", func() {
	It("requires the scanners, so a run always records what it looked for", func() {
		err := spec().ValidateConfig(map[string]any{"provider": ProviderImage})
		Expect(err).To(MatchError(ContainSubstring("scanners")))
	})

	It("refuses an empty scanner list", func() {
		err := spec().ValidateConfig(map[string]any{
			"provider": ProviderImage, "scanners": []any{}})
		Expect(err).To(MatchError(ContainSubstring("scanners")))
	})

	It("refuses a scanner trivy does not have, naming the element that is wrong", func() {
		err := spec().ValidateConfig(map[string]any{
			"provider": ProviderImage, "scanners": []any{"vuln", "typo"}})

		Expect(err).To(MatchError(ContainSubstring("/scanners/1")))
		// The allowed set is trivy's own, with no null among it: a list element
		// is never "unset", and offering one as a valid scanner reads as a bug.
		Expect(err).To(MatchError(ContainSubstring("'vuln', 'misconfig', 'secret', 'license'")))
		Expect(err).ToNot(MatchError(ContainSubstring("<nil>")))
	})

	It("refuses an unknown option rather than passing it to trivy", func() {
		err := spec().ValidateConfig(map[string]any{
			"provider": ProviderImage, "scanners": []any{"vuln"}, "nope": true})
		Expect(err).To(MatchError(ContainSubstring("nope")))
	})

	It("refuses a provider-specific option on the wrong provider", func() {
		// platform selects a variant of a multi-platform image; a repository
		// has none, and trivy would reject the flag long after the profile was
		// saved.
		err := spec().ValidateConfig(map[string]any{
			"provider": ProviderRepository, "scanners": []any{"secret"}, "platform": "linux/arm64"})
		Expect(err).To(MatchError(ContainSubstring("platform")))
	})

	DescribeTable("refuses an option whose scanner the profile does not run",
		func(option string, value any, scanner string) {
			err := spec().ValidateConfig(map[string]any{
				"provider": ProviderImage,
				// Deliberately not the scanner the option belongs to: trivy
				// accepts the combination and silently reports nothing it implies.
				"scanners": []any{"secret"},
				option:     value,
			})
			Expect(err).To(MatchError(ContainSubstring(option)))
			Expect(err).To(MatchError(ContainSubstring(scanner)))
		},
		Entry("only-fixed without the vulnerability scanner", "ignore-unfixed", true, "vuln"),
		Entry("a stale database without the vulnerability scanner", "skip-db-update", true, "vuln"),
		Entry("passes included without the misconfiguration scanner", "include-non-failures", true, "misconfig"),
		Entry("full detection without the licence scanner", "license-full", true, "license"),
	)

	It("accepts the option once its scanner is enabled", func() {
		Expect(spec().ValidateConfig(map[string]any{
			"provider": ProviderImage, "scanners": []any{"vuln"}, "ignore-unfixed": true,
		})).To(Succeed())
	})

	It("reads a disabled switch as trivy's own default rather than as a request", func() {
		// A form that writes every field submits ignore-unfixed: false, which
		// asks for nothing and must not be mistaken for asking for the vuln
		// scanner's behaviour.
		Expect(spec().ValidateConfig(map[string]any{
			"provider": ProviderImage, "scanners": []any{"secret"}, "ignore-unfixed": false,
		})).To(Succeed())
	})
})

var _ = Describe("the profiles trivy ships", func() {
	It("gives every provider a working profile, since nothing else creates one", func() {
		byProvider := map[string]int{}
		for _, profile := range spec().BuiltInProfiles() {
			By(profile.Name)
			Expect(spec().ValidateConfig(profile.Config)).To(Succeed())
			Expect(profile.Comment).ToNot(BeEmpty())
			byProvider[profile.Config["provider"].(string)]++
		}

		Expect(byProvider).To(Equal(map[string]int{
			ProviderImage: 2, ProviderRepository: 1, ProviderFilesystem: 1,
		}))
	})

	It("defaults to the image vulnerability scan", func() {
		defaults := spec().Defaults
		Expect(defaults.Name).To(Equal(defaultProfileName))
		Expect(defaults.Config["provider"]).To(Equal(ProviderImage))
		Expect(defaults.Config["scanners"]).To(Equal([]any{"vuln", "secret"}))
	})
})

var _ = Describe("the trivy engine", func() {
	It("scans provider contexts rather than endpoints", func() {
		// An image reference is not an address, and handing this engine one
		// would misrepresent what it scanned.
		Expect(spec().Subject).To(Equal(engines.SubjectProviderContexts))
	})

	It("is never intrusive, whatever it is configured to do", func() {
		for _, profile := range spec().BuiltInProfiles() {
			By(profile.Name)
			engine, err := newEngine()
			Expect(err).ToNot(HaveOccurred())
			// Every provider reads: an image is pulled, a repository cloned, a
			// directory walked. Nothing is sent to a running service.
			Expect(engine.Risk(profile.Config).Intrusive).To(BeFalse())
		}
	})

	It("keeps its provider table and its schema variants in step", func() {
		// The catalog is built from the table, so a variant with no entry is a
		// provider a run would resolve a schema for and then have no subcommand
		// to run. That every provider id is unique across engines is asserted
		// where every engine is registered, in internal/engines/all.
		for _, variant := range spec().Options.Variants {
			By(variant.ID)
			entry, err := find(variant.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(entry.Command).ToNot(BeEmpty())
			Expect(entry.Subject).ToNot(BeEmpty())
		}
	})
})
