package mute

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("deciding what an engine can take on", func() {
	It("pushes a rule that names only checks", func() {
		Expect(rule(api.MuteRule{Templates: api.StringList{"open-redirect"}}).Pushable()).
			To(Equal(DimensionTemplates))
	})

	It("pushes a rule that names only tags", func() {
		Expect(rule(api.MuteRule{Tags: api.StringList{"db-vendor"}}).Pushable()).To(Equal(DimensionTags))
	})

	It("pushes a rule that names only severities", func() {
		Expect(rule(api.MuteRule{Severity: api.StringList{"info"}}).Pushable()).
			To(Equal(DimensionSeverity))
	})

	// An engine's exclusions are a union while a rule's dimensions are an
	// intersection, so pushing this down would drop every info finding as well
	// as every open-redirect — and the checks would never run to notice.
	It("refuses a rule that names two dimensions", func() {
		two := api.MuteRule{Templates: api.StringList{"open-redirect"}, Severity: api.StringList{"info"}}
		Expect(rule(two).Pushable()).To(Equal(DimensionNone))
	})

	It("refuses a rule carrying an expression", func() {
		withExpr := api.MuteRule{Templates: api.StringList{"open-redirect"}, Expr: `finding.host == "x"`}
		Expect(rule(withExpr).Pushable()).To(Equal(DimensionNone))
	})

	// An exclusion list cannot say "everything not carrying this".
	It("refuses a negated value", func() {
		Expect(rule(api.MuteRule{Tags: api.StringList{"!dos"}}).Pushable()).To(Equal(DimensionNone))
		Expect(rule(api.MuteRule{Tags: api.StringList{"redirect", "!dos"}}).Pushable()).
			To(Equal(DimensionNone))
	})

	// Engine exclusions apply to the whole invocation, so a rule covering only
	// some of the run's subjects cannot become one.
	It("refuses a rule scoped to particular targets", func() {
		scoped := Rule{
			MuteRule: api.MuteRule{Templates: api.StringList{"open-redirect"}},
			Targets:  []string{"one.example.test"},
		}
		Expect(scoped.Pushable()).To(Equal(DimensionNone))
	})

	It("refuses a rule scoped to particular resources", func() {
		withResources := api.MuteRule{
			Templates: api.StringList{"open-redirect"}, Resources: api.StringList{"logs-*"},
		}
		Expect(rule(withResources).Pushable()).To(Equal(DimensionNone))
	})

	Describe("what is left to apply afterwards", func() {
		pushed := rule(api.MuteRule{Name: "pushed", Templates: api.StringList{"a"}})
		deferred := rule(api.MuteRule{Name: "deferred", Expr: `finding.host == "x"`})

		It("returns every rule when the engine took none", func() {
			plan := Plan{}
			Expect(plan.Deferred([]Rule{pushed, deferred})).To(HaveLen(2))
		})

		It("leaves out the rules the engine took on", func() {
			plan := Plan{PushedDown: map[string]string{"pushed": "exclude-id"}}
			remaining := plan.Deferred([]Rule{pushed, deferred})
			Expect(remaining).To(HaveLen(1))
			Expect(remaining[0].Name).To(Equal("deferred"))
			Expect(plan.Pushed("pushed")).To(BeTrue())
			Expect(plan.Pushed("deferred")).To(BeFalse())
		})
	})
})
