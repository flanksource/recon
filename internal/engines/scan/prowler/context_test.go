package prowler

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Prowler provider contexts", func() {
	It("rejects a profile/context collision instead of picking a winner", func() {
		_, err := mergeContextInputs(
			map[string]any{"compliance": []any{"cis_5.0_gcp"}},
			map[string]any{"compliance": []any{"pci_4.0_gcp"}},
		)
		Expect(err).To(MatchError(ContainSubstring(`argument "compliance" is set by both profile and provider context`)))
	})
})
