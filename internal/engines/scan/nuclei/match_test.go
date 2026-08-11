package nuclei

import (
	"context"
	"os"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"

	"github.com/flanksource/recon/internal/engines"
)

// installedIndex is the real template corpus, loaded once for the suite.
//
// These specs are about agreement with nuclei, so a fixture would defeat them:
// the question is whether the preview and the scanner select the same templates
// out of the same directory.
func installedIndex() *Index {
	GinkgoHelper()
	if os.Getenv("CI") == "" {
		if _, err := os.Stat(TemplatesDir()); err != nil {
			Skip("nuclei templates are not installed at " + TemplatesDir())
		}
	}
	loaded, err := SharedIndex()
	Expect(err).ToNot(HaveOccurred())
	return loaded
}

// loadedByNuclei is the set of template paths nuclei's own loader selects for a
// configuration — the scan's answer to the same question the preview answers.
func loadedByNuclei(config map[string]any) []string {
	GinkgoHelper()

	opts, err := Options(config)
	Expect(err).ToNot(HaveOccurred())

	engine, err := nuclei.NewNucleiEngineCtx(context.Background(), nuclei.WithOptions(opts))
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(engine.Close)
	Expect(engine.LoadAllTemplates()).To(Succeed())

	var paths []string
	for _, template := range engine.GetTemplates() {
		paths = append(paths, template.Path)
	}
	sort.Strings(paths)
	return paths
}

func matchedPaths(idx *Index, config map[string]any) []string {
	var paths []string
	for _, template := range idx.Select(config) {
		paths = append(paths, template.FilePath)
	}
	sort.Strings(paths)
	return paths
}

var _ = Describe("previewing what a profile would run", Label("templates"), func() {
	// The preview exists to be trusted before a scan, so the only assertion
	// worth making is that it agrees with the loader the scan itself uses. Both
	// sides read the same directory; if they ever disagree, the number shown to
	// someone about to scan production is wrong.
	DescribeTable("selects the same templates nuclei's loader does",
		func(config map[string]any) {
			idx := installedIndex()

			Expect(matchedPaths(idx, config)).To(Equal(loadedByNuclei(config)))
		},
		Entry("by tag", map[string]any{"tags": []any{"k8s", "kubernetes", "kubelet"}}),
		Entry("by protocol", map[string]any{"type": []any{"dns"}}),
		Entry("by severity", map[string]any{"severity": []any{"critical"}}),
		Entry("by tag and severity together", map[string]any{
			"tags": []any{"kev", "takeover"}, "severity": []any{"critical", "high"},
		}),
		Entry("by author", map[string]any{"author": []any{"pdteam"}, "severity": []any{"critical"}}),
		Entry("with an exclusion", map[string]any{
			"tags": []any{"ssl"}, "exclude-tags": []any{"tls"},
		}),
		Entry("with a template id", map[string]any{"template-id": []any{"CVE-2024-*"}}),
		Entry("from a directory", map[string]any{"templates": []any{"dns/"}}),
		Entry("with code templates enabled", map[string]any{
			"tags": []any{"k8s-cluster-security"}, "code": true,
		}),
	)

	// One profile per shape rather than all of them: building a nuclei engine
	// and loading the corpus costs seconds each, and the profiles differ only in
	// which of the mechanisms above they combine. These four cover the widest
	// selection, the narrowest, DAST with a template directory, and an imported
	// community profile.
	//
	// Profiles that enable code templates are deliberately absent: whether one
	// loads depends on the interpreters installed on this machine, which Preview
	// reports as a caveat rather than pretending to know.
	DescribeTable("previews exactly what a shipped profile would run",
		func(name string) {
			idx := installedIndex()
			profile := builtIn(name)

			Expect(matchedPaths(idx, profile.Config)).To(Equal(loadedByNuclei(profile.Config)),
				"profile %q previews a different set than it would run", name)
		},
		Entry("safe", "safe"),
		Entry("full", "full"),
		Entry("k8s", "k8s"),
		Entry("kev", "kev"),
	)

	It("gives every shipped profile a selection to preview", func() {
		// A profile that matches nothing is a typo — a tag the corpus does not
		// use, or a filter combination with no overlap. It costs nothing to
		// catch here and is invisible until someone runs it and finds no
		// findings, which looks like good news.
		idx := installedIndex()

		empty := map[string]int{}
		for _, profile := range (Engine{}).Spec().BuiltInProfiles() {
			if total := idx.Match(profile.Config).Total; total == 0 {
				empty[profile.Name] = total
			}
		}

		Expect(empty).To(BeEmpty(), "profiles that select no templates at all")
	})

	It("says a code profile's count depends on the host", func() {
		idx := installedIndex()

		preview := idx.Match(builtIn("windows-audit").Config)

		Expect(preview.Unsupported).To(ContainElement(ContainSubstring("interpreter")))
	})
})

func builtIn(name string) engines.DefaultProfile {
	GinkgoHelper()
	for _, profile := range (Engine{}).Spec().BuiltInProfiles() {
		if profile.Name == name {
			return profile
		}
	}
	Fail("no built-in profile named " + name)
	return engines.DefaultProfile{}
}

var _ = Describe("the template index", Label("templates"), func() {
	It("reads the whole corpus", func() {
		idx := installedIndex()

		Expect(len(idx.Templates)).To(BeNumerically(">", 10_000),
			"the community template set is far larger than this")
	})

	It("records the metadata a browser filters on", func() {
		idx := installedIndex()

		var withSeverity, withTags, withType int
		for _, template := range idx.Templates {
			if template.Severity != "" {
				withSeverity++
			}
			if len(template.Tags) > 0 {
				withTags++
			}
			if template.ProtocolType != "" {
				withType++
			}
		}

		// Not "every template", because the corpus does contain a few without
		// tags — but a decoding bug shows up as most of them being empty, which
		// is exactly what silently breaks every filter downstream.
		total := len(idx.Templates)
		Expect(withSeverity).To(BeNumerically(">", total*9/10))
		Expect(withTags).To(BeNumerically(">", total*9/10))
		Expect(withType).To(Equal(total))
	})

	It("summarises a match without listing all of it", func() {
		idx := installedIndex()

		preview := idx.Match(map[string]any{"tags": []any{"panel", "login"}})

		Expect(preview.Total).To(BeNumerically(">", PreviewLimit))
		Expect(preview.Templates).To(HaveLen(PreviewLimit))
		Expect(preview.Truncated).To(BeTrue())
		Expect(preview.ByTag).ToNot(BeEmpty())
		Expect(len(preview.ByTag)).To(BeNumerically("<=", TopTags))
	})

	It("says so when a filter it cannot evaluate would narrow the result", func() {
		idx := installedIndex()

		preview := idx.Match(map[string]any{
			"tags":               []any{"dns"},
			"template-condition": []any{`contains(tags, "dns")`},
		})

		Expect(preview.Unsupported).To(ContainElement(ContainSubstring("template-condition")))
	})
})
