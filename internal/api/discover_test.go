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
			Profiles: map[string]string{},
			Input:    map[string]any{},
			Hosts:    []api.DiscoveredHost{},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(encoded).To(MatchJSON(`{
			"id": "",
			"chain": "",
			"profiles": {},
			"input": {},
			"ranAt": "",
			"durationMs": 0,
			"failed": false,
			"log": "",
			"hosts": []
		}`))
	})

	It("reports the profile each engine ran with", func() {
		encoded, err := json.Marshal(api.Discover{
			Profiles: map[string]string{"naabu": "full-ports", "httpx": "default"},
			Input:    map[string]any{},
			Hosts:    []api.DiscoveredHost{},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(encoded).To(ContainSubstring(`"profiles":{"httpx":"default","naabu":"full-ports"}`))
	})
})
