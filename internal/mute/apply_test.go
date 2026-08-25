package mute

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/ocsf"
)

// run builds a findings slice whose severities alternate, so a rule can remove
// some without removing all and the surviving line numbers have gaps.
func run(count int) []api.Finding {
	findings := make([]api.Finding, 0, count)
	for i := range count {
		severity := ocsf.SeverityIDLow
		if i%2 == 0 {
			severity = ocsf.SeverityIDHigh
		}
		findings = append(findings, api.Finding{
			DetectionFinding: ocsf.DetectionFinding{SeverityID: severity},
			CheckID:          fmt.Sprintf("check-%d", i),
			Host:             "example.test",
		})
	}
	return findings
}

var _ = Describe("applying rules to a run", func() {
	It("keeps everything when no rule is in force", func() {
		result := Apply(nil, run(3))
		Expect(result.Kept).To(HaveLen(3))
		Expect(result.Muted).To(Equal(0))
		Expect(result.ByRule).To(BeEmpty())
	})

	// line_no is the line of the engine's own findings file. Renumbering the
	// survivors would break the only correspondence that lets someone read the
	// run's directory without a database and see what was removed.
	It("stamps every kept finding with the line it came from", func() {
		result := Apply(nil, run(3))
		Expect(result.Kept[0].LineNo).To(Equal(1))
		Expect(result.Kept[1].LineNo).To(Equal(2))
		Expect(result.Kept[2].LineNo).To(Equal(3))
	})

	It("leaves gaps in the line numbers rather than renumbering", func() {
		high := rule(api.MuteRule{Name: "no-high", Severity: api.StringList{"high"}})

		result := Apply([]Rule{high}, run(5))

		Expect(result.Muted).To(Equal(3))
		// Lines 1, 3 and 5 were high and are gone; 2 and 4 keep their own lines.
		Expect(result.Kept).To(HaveLen(2))
		Expect(result.Kept[0].LineNo).To(Equal(2))
		Expect(result.Kept[1].LineNo).To(Equal(4))
	})

	It("records which lines each rule removed", func() {
		high := rule(api.MuteRule{Name: "no-high", Severity: api.StringList{"high"}})

		result := Apply([]Rule{high}, run(5))

		Expect(result.ByRule).To(HaveKeyWithValue("no-high", []int{1, 3, 5}))
	})

	// A finding is muted once. Attributing it to the first matching rule keeps
	// mutes.json readable, and the store returns rules by name so the
	// attribution does not depend on row order.
	It("attributes a finding to the first rule that matched", func() {
		first := rule(api.MuteRule{Name: "a-first", Severity: api.StringList{"high"}})
		second := rule(api.MuteRule{Name: "b-second", Templates: api.StringList{"check-0"}})

		result := Apply([]Rule{first, second}, run(2))

		Expect(result.ByRule).To(HaveKeyWithValue("a-first", []int{1}))
		Expect(result.ByRule).ToNot(HaveKey("b-second"))
	})

	Describe("a rule that cannot be evaluated", func() {
		broken := rule(api.MuteRule{Name: "broken", Expr: `finding.host`})

		It("mutes nothing", func() {
			result := Apply([]Rule{broken}, run(4))
			Expect(result.Kept).To(HaveLen(4))
			Expect(result.Muted).To(Equal(0))
		})

		It("is reported once however many findings it saw", func() {
			result := Apply([]Rule{broken}, run(50))
			Expect(result.Errors).To(HaveLen(1))
			Expect(result.Errors).To(HaveKey("broken"))
		})

		It("does not stop a later rule from applying", func() {
			working := rule(api.MuteRule{Name: "working", Severity: api.StringList{"high"}})
			result := Apply([]Rule{broken, working}, run(4))
			Expect(result.Muted).To(Equal(2))
			Expect(result.Errors).To(HaveKey("broken"))
		})
	})

	// gomplate caches a compiled program under the environment's variable names
	// plus the expression, and declines to cache when a template carries its own
	// functions. A single fixed variable is what keeps that cache warm; if the
	// environment ever grows a second name or a custom function, this stops
	// being one compile and becomes one per finding.
	It("evaluates a large run through one expression without slowing down", func() {
		expression := rule(api.MuteRule{Name: "expr", Expr: `finding.severity_id == 4`})

		result := Apply([]Rule{expression}, run(2000))

		Expect(result.Muted).To(Equal(1000))
		Expect(result.Errors).To(BeEmpty())
	})
})
