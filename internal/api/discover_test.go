package api_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("discovery API", func() {
	It("always emits the log string consumed by the ANSI renderer", func() {
		encoded, err := json.Marshal(api.Discover{
			Input: map[string]any{},
			Hosts: []api.DiscoveredHost{},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(encoded).To(MatchJSON(`{
			"id": "",
			"chain": "",
			"profile": "",
			"input": {},
			"ranAt": "",
			"durationMs": 0,
			"failed": false,
			"log": "",
			"hosts": []
		}`))
	})
})
