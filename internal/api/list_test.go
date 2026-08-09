package api_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// An edit is one operation reachable two ways, and the two do not encode a list
// alike. The HTTP body is flattened into CLI flags before the handler sees it,
// so even a JSON array arrives comma-joined — a saved profile came back as
// "cannot unmarshal string into []string", and the edit was lost.
var _ = Describe("a curated edit", func() {
	It("takes a list field as an array", func() {
		curated, err := api.CuratedFrom(map[string]any{
			"class":    "non-prod",
			"profiles": []any{"safe", "full"},
			"tags":     []any{"http"},
			"ports":    []any{80, 443},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(curated.Profiles).To(Equal(api.StringList{"safe", "full"}))
		Expect(curated.Tags).To(Equal(api.StringList{"http"}))
		Expect(curated.Ports).To(Equal(api.IntList{80, 443}))
	})

	It("takes the same list comma-joined, which is what a flag produces", func() {
		curated, err := api.CuratedFrom(map[string]any{
			"class":    "non-prod",
			"profiles": "safe,full",
			"tags":     "http",
			"ports":    "80,443",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(curated.Profiles).To(Equal(api.StringList{"safe", "full"}))
		Expect(curated.Tags).To(Equal(api.StringList{"http"}))
		Expect(curated.Ports).To(Equal(api.IntList{80, 443}))
	})

	It("ignores the blank entries a trailing separator leaves", func() {
		// "safe," would otherwise become a list holding an empty name, which the
		// schema rejects for a reason that names neither the field nor the comma.
		curated, err := api.CuratedFrom(map[string]any{
			"class": "non-prod", "profiles": "safe, ,", "tags": "",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(curated.Profiles).To(Equal(api.StringList{"safe"}))
		Expect(curated.Tags).To(BeEmpty())
	})

	It("refuses a port that is not a number rather than dropping it", func() {
		_, err := api.CuratedFrom(map[string]any{
			"class": "non-prod", "profiles": "safe", "tags": "", "ports": "80,http",
		})
		Expect(err).To(MatchError(ContainSubstring(`"http" is not a port number`)))
	})

	It("still emits an empty list rather than null", func() {
		// The frontend maps over these without checking.
		curated, err := api.CuratedFrom(map[string]any{"class": "non-prod"})
		Expect(err).ToNot(HaveOccurred())

		encoded, err := curated.Profiles.MarshalJSON()
		Expect(err).ToNot(HaveOccurred())
		Expect(string(encoded)).To(Equal("[]"))
	})
})
