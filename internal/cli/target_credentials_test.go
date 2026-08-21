package cli

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("target import credentials", func() {
	It("preserves stored credentials when importing a redacted API document", func() {
		definition := definitionOnly(map[string]any{
			"id": "cloudflare-production",
			"credentials": map[string]any{"envVars": []any{map[string]any{
				"name": "CLOUDFLARE_API_TOKEN", "configured": true,
			}}},
		})

		Expect(definition).ToNot(HaveKey("credentials"))
	})

	It("keeps authored credential values so imports can replace them", func() {
		credentials := map[string]any{"envVars": []any{map[string]any{
			"name": "CLOUDFLARE_API_TOKEN", "value": "replacement",
		}}}
		definition := definitionOnly(map[string]any{
			"id": "cloudflare-production", "credentials": credentials,
		})

		Expect(definition).To(HaveKeyWithValue("credentials", credentials))
	})

	It("preserves stored credentials when a nested connection is redacted", func() {
		definition := definitionOnly(map[string]any{
			"id": "kubernetes-production",
			"credentials": map[string]any{"connections": map[string]any{
				"kubernetes": map[string]any{"gke": map[string]any{
					"credentials": map[string]any{"configured": true},
				}},
			}},
		})

		Expect(definition).ToNot(HaveKey("credentials"))
	})
})
