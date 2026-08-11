package entities

import (
	"context"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	_ "github.com/flanksource/recon/internal/engines/all"
	"github.com/flanksource/recon/internal/engines/scan/nuclei"
)

// The template catalogue is read from the installed templates, not from the
// database, so these specs need no store — which is the point: "what would this
// run" is answerable on a machine that has never opened a connection.
var _ = Describe("the template catalogue", Label("templates"), func() {
	var registry *Registry

	BeforeEach(func() {
		if _, err := os.Stat(nuclei.TemplatesDir()); err != nil {
			Skip("nuclei templates are not installed at " + nuclei.TemplatesDir())
		}
		registry = &Registry{}
	})

	list := func(opts TemplateOpts) []api.Template {
		GinkgoHelper()
		templates, err := registry.listTemplates(context.Background(), opts)
		Expect(err).ToNot(HaveOccurred())
		return templates
	}

	It("gives a filter the whole catalogue to build its vocabulary from", func() {
		// A negative limit means "all". Capping it derived the offered tags and
		// protocols from the first 500 templates, so the Protocol filter listed
		// three of nuclei's protocols and the Tag filter missed most tags.
		all := list(TemplateOpts{Limit: -1})
		Expect(len(all)).To(BeNumerically(">", templateLimit))

		protocols := map[string]bool{}
		for _, template := range all {
			protocols[template.Type] = true
		}
		Expect(len(protocols)).To(BeNumerically(">", 3))
	})

	It("lists templates without a database", func() {
		templates := list(TemplateOpts{Limit: 10})

		Expect(templates).To(HaveLen(10))
		for _, template := range templates {
			Expect(template.ID).ToNot(BeEmpty())
			Expect(template.Engine).To(Equal("nuclei"))
			Expect(template.Path).ToNot(BeEmpty())
		}
	})

	It("reports paths relative to the template set, not to this machine", func() {
		// An absolute path would name a directory that exists only here, which
		// is exactly the sort of thing that ends up in a report and confuses the
		// person reading it on another machine.
		templates := list(TemplateOpts{Limit: 5})

		for _, template := range templates {
			Expect(template.Path).ToNot(HavePrefix("/"))
		}
	})

	It("narrows by severity", func() {
		templates := list(TemplateOpts{Severity: []string{"critical"}, Limit: 50})

		Expect(templates).ToNot(BeEmpty())
		for _, template := range templates {
			Expect(template.Severity).To(Equal("critical"))
		}
	})

	It("narrows by protocol", func() {
		templates := list(TemplateOpts{Type: []string{"dns"}, Limit: 50})

		Expect(templates).ToNot(BeEmpty())
		for _, template := range templates {
			Expect(template.Type).To(Equal("dns"))
		}
	})

	It("narrows by tag", func() {
		templates := list(TemplateOpts{Tag: []string{"kubernetes"}, Limit: 50})

		Expect(templates).ToNot(BeEmpty())
		for _, template := range templates {
			Expect(template.Tags).To(ContainElement("kubernetes"))
		}
	})

	It("combines filters as an intersection", func() {
		templates := list(TemplateOpts{
			Type: []string{"dns"}, Severity: []string{"info"}, Limit: 100,
		})

		Expect(templates).ToNot(BeEmpty())
		for _, template := range templates {
			Expect([]string{template.Type, template.Severity}).To(Equal([]string{"dns", "info"}))
		}
	})

	It("searches id, name and description", func() {
		templates := list(TemplateOpts{Search: "dmarc", Limit: 20})

		Expect(templates).ToNot(BeEmpty())
	})

	It("bounds an unfiltered listing rather than returning the whole corpus", func() {
		// Thirteen thousand rows is not a page, and a caller that forgot a limit
		// should get a page rather than the catalogue.
		Expect(list(TemplateOpts{})).To(HaveLen(templateLimit))
	})

	It("rejects an engine that has no catalogue", func() {
		_, err := registry.listTemplates(context.Background(), TemplateOpts{Engine: []string{"nmap"}})

		Expect(err).To(MatchError(ContainSubstring("no scan engine")))
	})
})

var _ = Describe("previewing a draft configuration", Label("templates"), func() {
	var registry *Registry

	BeforeEach(func() {
		if _, err := os.Stat(nuclei.TemplatesDir()); err != nil {
			Skip("nuclei templates are not installed at " + nuclei.TemplatesDir())
		}
		registry = &Registry{}
	})

	It("summarises what a configuration would run", func() {
		preview, err := registry.PreviewTemplates("nuclei", map[string]any{
			"tags": []any{"kubernetes", "kubelet"},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(preview.Engine).To(Equal("nuclei"))
		Expect(preview.Total).To(BeNumerically(">", 0))
		Expect(preview.BySeverity).ToNot(BeEmpty())
		Expect(preview.ByType).ToNot(BeEmpty())
		Expect(preview.MaxRequests).To(BeNumerically(">", 0))
	})

	It("defaults to nuclei so a caller that knows only one engine need not say so", func() {
		preview, err := registry.PreviewTemplates("", map[string]any{"type": []any{"dns"}})

		Expect(err).ToNot(HaveOccurred())
		Expect(preview.Engine).To(Equal("nuclei"))
	})

	It("refuses a configuration the engine itself would reject", func() {
		// Previewing an unrunnable configuration would answer a question the
		// scan cannot be asked.
		_, err := registry.PreviewTemplates("nuclei", map[string]any{
			"automatic-scan": true,
			"dast":           true,
		})

		Expect(err).To(MatchError(ContainSubstring("automatic-scan cannot be combined with dast")))
	})

	It("refuses an option the catalog does not declare", func() {
		_, err := registry.PreviewTemplates("nuclei", map[string]any{"rate-limitt": 5})

		Expect(err).To(HaveOccurred())
	})
})

// Excluding is what the tri-state filter controls send: a value the user turned
// to "exclude" arrives as `!value` on the same query parameter. It has to mean
// the same thing here as it does in SQL and on the CLI, or the control would
// promise a narrowing the listing does not perform.
var _ = Describe("narrowing templates by tag and protocol", func() {
	catalogue := []api.Template{
		{ID: "kubelet-metrics", Type: "http", Tags: []string{"k8s", "exposure"}},
		{ID: "docker-registry", Type: "http", Tags: []string{"k8s", "docker"}},
		{ID: "caa-fingerprint", Type: "dns", Tags: []string{"dns"}},
		{ID: "network-dos", Type: "network", Tags: []string{"network", "dos"}},
		{ID: "untagged", Type: "http"},
	}

	ids := func(opts TemplateOpts) []string {
		GinkgoHelper()
		var out []string
		for _, template := range filterTemplates(append([]api.Template(nil), catalogue...), opts) {
			out = append(out, template.ID)
		}
		return out
	}

	It("keeps every template when nothing is selected", func() {
		Expect(ids(TemplateOpts{})).To(HaveLen(len(catalogue)))
	})

	It("includes the tags asked for", func() {
		Expect(ids(TemplateOpts{Tag: []string{"k8s"}})).
			To(ConsistOf("kubelet-metrics", "docker-registry"))
	})

	It("drops a template carrying an excluded tag, whatever else it carries", func() {
		// The failure this guards: treating exclusion as "any tag survives"
		// keeps docker-registry because it is also tagged k8s.
		Expect(ids(TemplateOpts{Tag: []string{"!docker"}})).
			To(ConsistOf("kubelet-metrics", "caa-fingerprint", "network-dos", "untagged"))
	})

	It("applies an exclusion on top of an inclusion", func() {
		Expect(ids(TemplateOpts{Tag: []string{"k8s", "!docker"}})).
			To(ConsistOf("kubelet-metrics"))
	})

	It("keeps an untagged template out of an inclusion but inside an exclusion", func() {
		Expect(ids(TemplateOpts{Tag: []string{"k8s"}})).ToNot(ContainElement("untagged"))
		Expect(ids(TemplateOpts{Tag: []string{"!docker"}})).To(ContainElement("untagged"))
	})

	It("excludes a protocol", func() {
		Expect(ids(TemplateOpts{Type: []string{"!http"}})).
			To(ConsistOf("caa-fingerprint", "network-dos"))
	})

	It("combines an included protocol with an excluded tag", func() {
		Expect(ids(TemplateOpts{Type: []string{"http"}, Tag: []string{"!docker"}})).
			To(ConsistOf("kubelet-metrics", "untagged"))
	})

	It("matches case-insensitively, as the include-only filter always did", func() {
		Expect(ids(TemplateOpts{Type: []string{"HTTP"}})).
			To(ConsistOf("kubelet-metrics", "docker-registry", "untagged"))
	})
})
