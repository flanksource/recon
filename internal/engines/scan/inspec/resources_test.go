package inspec

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// The verdicts an InSpec run carries, which are what lets a later run resolve
// an earlier one's findings.
//
// InSpec reports passed/failed/skipped/error per control, so unlike nuclei and
// trivy it can say a control that failed now passes. Getting the mapping wrong
// in the permissive direction resolves a finding that is still true.
var _ = Describe("what an InSpec run concluded", func() {
	// A control with several describe blocks, mixed. This is the case the
	// mapping has to get right: InSpec reports per result, not per control, and
	// a control with twenty describe blocks of which one failed has nineteen
	// passing results — so a naive per-result mapping would record it as both
	// failing and passing at once, and the pass would resolve the failure.
	report := func(results ...Result) ExecJSON {
		return ExecJSON{Profiles: []Profile{{
			Name:     "inspec-gcp-cis-benchmark",
			Controls: []Control{{ID: "cis-gcp-5.1", Results: results}},
		}}}
	}

	It("names the account once, whatever the controls said", func() {
		resources := report(Result{Status: StatusPassed}).Resources(account)

		Expect(resources).To(HaveLen(1))
		Expect(resources[0].UID).To(Equal(account))
		Expect(resources[0].Kind).To(Equal(api.KindAccount))
		Expect(resources[0].Key().Validate()).To(Succeed())
	})

	It("links every failure to the emitted account resource", func() {
		parsed := report(Result{Status: StatusFailed})

		findings, err := parsed.Findings(account)
		Expect(err).ToNot(HaveOccurred())
		Expect(findings).To(HaveLen(1))
		Expect(findings[0].Resources).To(Equal([]api.ResourceRef{
			parsed.Resources(account)[0].Ref(),
		}))
		Expect(parsed.Resources(account)[0].ExternalIDs).To(ContainElement(account))
	})

	DescribeTable("records a control as passed only when nothing in it failed",
		func(passed bool, results ...Result) {
			verdicts := report(results...).Resources(account)[0].Passed

			if passed {
				Expect(verdicts).To(ConsistOf("cis-gcp-5.1"))
				return
			}
			Expect(verdicts).To(BeEmpty())
		},
		Entry("every block passed", true,
			Result{Status: StatusPassed}, Result{Status: StatusPassed}),
		Entry("one block failed", false,
			Result{Status: StatusPassed}, Result{Status: StatusFailed}),
		// The two that are neither. A control that could not run has proved
		// nothing, and counting it as a pass would resolve a finding on the
		// strength of a check that never executed.
		Entry("a block errored", false,
			Result{Status: StatusPassed}, Result{Status: StatusError}),
		Entry("every block was skipped", false, Result{Status: StatusSkipped}),
		Entry("nothing ran at all", false),
	)

	It("claims each control once however many blocks passed", func() {
		verdicts := report(
			Result{Status: StatusPassed},
			Result{Status: StatusPassed},
			Result{Status: StatusPassed},
		).Resources(account)[0].Passed

		Expect(verdicts).To(HaveLen(1), "a verdict is per control, not per describe block")
	})

	// The real fixture, so the mapping is exercised against the shape the tool
	// actually emits rather than only against hand-built controls.
	It("agrees with the report's own tally on the real fixture", func() {
		parsed := load()
		verdicts := parsed.Resources(account)[0].Passed

		// Every control it calls passed must have produced no finding, which is
		// the invariant the lifecycle depends on: one control cannot be both
		// the evidence of a problem and the proof that it is gone.
		findings, err := parsed.Findings(account)
		Expect(err).ToNot(HaveOccurred())
		failing := map[string]struct{}{}
		for _, finding := range findings {
			failing[finding.CheckID] = struct{}{}
		}
		for _, control := range verdicts {
			Expect(failing).ToNot(HaveKey(control),
				"%s is reported both passing and failing", control)
		}
	})
})
