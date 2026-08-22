package api_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("a mute rule", func() {
	It("accepts a rule that names a check", func() {
		rule := api.MuteRule{Name: "accepted-open-redirect", Templates: api.StringList{"open-redirect"}}
		Expect(rule.Validate()).To(Succeed())
	})

	It("refuses a rule that selects nothing", func() {
		err := api.MuteRule{Name: "everything"}.Validate()
		Expect(err).To(MatchError(ContainSubstring("selects nothing")))
	})

	// Engines says which runs a rule is considered for, not which findings it
	// matches. Counting it would let `engines=nuclei` read as a filter while
	// muting every finding nuclei produced.
	It("refuses a rule carrying only an engine", func() {
		err := api.MuteRule{Name: "all-nuclei", Engines: api.StringList{"nuclei"}}.Validate()
		Expect(err).To(MatchError(ContainSubstring("selects nothing")))
	})

	It("accepts a rule carrying only an expression", func() {
		rule := api.MuteRule{Name: "logs-buckets", Expr: `finding.host.startsWith("logs-")`}
		Expect(rule.Validate()).To(Succeed())
	})

	It("refuses a name that could not be a filename fragment", func() {
		Expect(api.MuteRule{Name: "Accepted Risk", Templates: api.StringList{"x"}}.Validate()).
			To(MatchError(ContainSubstring("invalid mute rule name")))
		Expect(api.MuteRule{Templates: api.StringList{"x"}}.Validate()).
			To(MatchError(ContainSubstring("name is required")))
	})

	It("refuses a severity outside the ladder", func() {
		err := api.MuteRule{Name: "typo", Severity: api.StringList{"hgih"}}.Validate()
		Expect(err).To(MatchError(ContainSubstring("unknown severity")))
	})

	It("accepts unknown as a severity, because findings carry it", func() {
		Expect(api.MuteRule{Name: "unclassified", Severity: api.StringList{"unknown"}}.Validate()).
			To(Succeed())
	})

	Describe("which runs it applies to", func() {
		It("applies to every engine when none is named", func() {
			rule := api.MuteRule{Name: "any", Templates: api.StringList{"x"}}
			Expect(rule.AppliesTo("nuclei")).To(BeTrue())
			Expect(rule.AppliesTo("inspec")).To(BeTrue())
		})

		It("applies only to the engines it names", func() {
			rule := api.MuteRule{Name: "one", Templates: api.StringList{"x"}, Engines: api.StringList{"nuclei"}}
			Expect(rule.AppliesTo("nuclei")).To(BeTrue())
			Expect(rule.AppliesTo("trivy")).To(BeFalse())
		})
	})

	It("is out of force while disabled", func() {
		Expect(api.MuteRule{Name: "off", Disabled: true}.Active()).To(BeFalse())
		Expect(api.MuteRule{Name: "on"}.Active()).To(BeTrue())
	})
})

var _ = Describe("decoding a mute rule from a request body", func() {
	// The HTTP body is flattened into flags before it reaches the handler, so a
	// list arrives comma-joined even when the caller sent a JSON array.
	It("reads a list from either wire form", func() {
		fromFlag, err := api.MuteRuleFrom(map[string]any{"name": "r", "templates": "a,b"})
		Expect(err).ToNot(HaveOccurred())
		Expect(fromFlag.Templates).To(ConsistOf("a", "b"))

		fromJSON, err := api.MuteRuleFrom(map[string]any{"name": "r", "templates": []any{"a", "b"}})
		Expect(err).ToNot(HaveOccurred())
		Expect(fromJSON.Templates).To(ConsistOf("a", "b"))
	})

	It("reads the target selector from either wire form", func() {
		fromFlag, err := api.MuteRuleFrom(map[string]any{
			"name": "r", "targets": `{"class":["non-prod"]}`,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(fromFlag.Targets).To(HaveKey("class"))

		fromJSON, err := api.MuteRuleFrom(map[string]any{
			"name": "r", "targets": map[string]any{"class": []any{"non-prod"}},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(fromJSON.Targets).To(HaveKey("class"))
	})

	It("reports a typo rather than ignoring it", func() {
		_, err := api.MuteRuleFrom(map[string]any{"name": "r", "template": "a"})
		Expect(err).To(MatchError(ContainSubstring("template")))
	})

	It("reports a target selector that is not an object", func() {
		_, err := api.MuteRuleFrom(map[string]any{"name": "r", "targets": "not json"})
		Expect(err).To(MatchError(ContainSubstring("targets must be a JSON object")))
	})
})
