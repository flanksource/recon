package api_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("provider-context targets", func() {
	It("decodes a stable provider context without pretending it is a host", func() {
		target, err := api.TargetFrom(map[string]any{
			"id":             "gcp-production",
			"kind":           "provider-context",
			"provider":       "gcp",
			"credentialMode": "ambient",
			"arguments": map[string]any{
				"project-ids": []any{"workload-prod-eu-02", "flanksource-prod"},
			},
			"class":    "prod",
			"profiles": []any{"scan:prowler:gcp-cis-5-0"},
			"tags":     []any{},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(target.ID).To(Equal("gcp-production"))
		Expect(target.Host).To(BeEmpty())
		Expect(target.Kind).To(Equal(api.KindProviderContext))
		Expect(target.Provider).To(Equal("gcp"))
		Expect(target.CredentialMode).To(Equal(api.CredentialAmbient))
		Expect(target.Arguments).To(Equal(map[string]any{
			"project-ids": []any{"workload-prod-eu-02", "flanksource-prod"},
		}))
	})

	// The HTTP executor flattens every top-level body value to a string before a
	// handler sees it, so this — not the object above — is the shape a request
	// from the browser or the CLI actually arrives in. Accepting only the object
	// form made a provider context impossible to create or edit over the API at
	// all: every request the UI could send came back "arguments must be an
	// object".
	It("takes arguments as the JSON string the HTTP executor produces", func() {
		target, err := api.TargetFrom(map[string]any{
			"id":             "gcp-production",
			"kind":           "provider-context",
			"provider":       "gcp",
			"credentialMode": "ambient",
			"arguments":      `{"project-ids":["workload-prod-eu-02"]}`,
			"class":          "prod",
			"profiles":       "scan:prowler:gcp-cis-5-0",
			"tags":           "",
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(target.Arguments).To(Equal(map[string]any{
			"project-ids": []any{"workload-prod-eu-02"},
		}))
	})

	It("takes an edit's arguments in the same two forms", func() {
		update, err := api.TargetUpdateFrom(map[string]any{
			"class": "prod", "profiles": "scan:prowler:gcp-cis-5-0", "tags": "",
			"arguments": `{"project-ids":["workload-prod-eu-02"]}`,
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(*update.Arguments).To(Equal(map[string]any{
			"project-ids": []any{"workload-prod-eu-02"},
		}))
	})

	It("reports arguments that are neither an object nor JSON", func() {
		_, err := api.TargetFrom(map[string]any{
			"id": "gcp-production", "kind": "provider-context",
			"provider": "gcp", "credentialMode": "ambient",
			"arguments": "not json at all",
			"class":     "prod", "profiles": "scan:prowler:gcp-cis-5-0", "tags": "",
		})

		Expect(err).To(MatchError(ContainSubstring("arguments must be a JSON object")))
	})

	It("defaults a host id to its address", func() {
		target, err := api.TargetFrom(map[string]any{
			"host": "api.example.test", "class": "non-prod",
			"profiles": []any{"scan:nuclei:safe"}, "tags": []any{},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(target.ID).To(Equal("api.example.test"))
		Expect(target.Host).To(Equal("api.example.test"))
	})

	DescribeTable("rejects incomplete provider identities",
		func(body map[string]any, problem string) {
			_, err := api.TargetFrom(body)
			Expect(err).To(MatchError(ContainSubstring(problem)))
		},
		Entry("missing id", map[string]any{
			"kind": "provider-context", "provider": "gcp", "credentialMode": "ambient",
			"class": "prod", "profiles": []any{"scan:prowler:gcp-cis-5-0"}, "tags": []any{},
		}, "id is required"),
		Entry("host supplied", map[string]any{
			"id": "gcp-production", "host": "workload-prod-eu-02", "kind": "provider-context",
			"provider": "gcp", "credentialMode": "ambient", "class": "prod",
			"profiles": []any{"scan:prowler:gcp-cis-5-0"}, "tags": []any{},
		}, "provider-context cannot have a host"),
		Entry("missing provider", map[string]any{
			"id": "production", "kind": "provider-context", "credentialMode": "ambient",
			"class": "prod", "profiles": []any{"scan:prowler:gcp-cis-5-0"}, "tags": []any{},
		}, "provider is required"),
		Entry("missing credential mode", map[string]any{
			"id": "production", "kind": "provider-context", "provider": "gcp",
			"class": "prod", "profiles": []any{"scan:prowler:gcp-cis-5-0"}, "tags": []any{},
		}, "credentialMode is required"),
		Entry("provider fields on host", map[string]any{
			"host": "api.example.test", "provider": "gcp", "class": "prod",
			"profiles": []any{"scan:nuclei:safe"}, "tags": []any{},
		}, "a host cannot have provider context"),
	)

	It("marshals an addressless provider context", func() {
		body, err := json.Marshal(api.TargetDocument{
			ID: "github-flanksource", Kind: api.KindProviderContext,
			Provider: "github", CredentialMode: api.CredentialConfigured,
			Arguments: map[string]any{"organizations": []any{"flanksource"}},
			Class:     api.ClassProd, Profiles: []string{"scan:prowler:github-cis"}, Tags: []string{},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(MatchJSON(`{
			"$schema":"../target.schema.json","version":3,"id":"github-flanksource",
			"kind":"provider-context","provider":"github","credentialMode":"configured",
			"arguments":{"organizations":["flanksource"]},"class":"prod",
			"profiles":["scan:prowler:github-cis"],"tags":[]
		}`))
	})

	It("decodes an atomic provider-context edit without accepting identity changes", func() {
		update, err := api.TargetUpdateFrom(map[string]any{
			"credentialMode": "configured",
			"arguments":      map[string]any{"project-ids": []any{"example-prod"}},
			"class":          "prod",
			"profiles":       []any{"scan:prowler:gcp-cis-5-0"},
			"tags":           []any{"critical"},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(update.CredentialMode).To(HaveValue(Equal(api.CredentialConfigured)))
		Expect(update.Arguments).To(HaveValue(Equal(map[string]any{
			"project-ids": []any{"example-prod"},
		})))
		Expect(update.Curated.Tags).To(Equal(api.StringList{"critical"}))
	})

	DescribeTable("keeps provider identity immutable on edit",
		func(field string, value any) {
			_, err := api.TargetUpdateFrom(map[string]any{
				field: value, "class": "prod", "profiles": []any{"scan:prowler:gcp-cis-5-0"},
			})
			Expect(err).To(MatchError(ContainSubstring(field + " is not editable")))
		},
		Entry("id", "id", "different"),
		Entry("host", "host", "different.example.test"),
		Entry("kind", "kind", "host"),
		Entry("provider", "provider", "aws"),
	)

	It("rejects an invalid credential mode on edit", func() {
		_, err := api.TargetUpdateFrom(map[string]any{
			"credentialMode": "inline-secret", "class": "prod",
			"profiles": []any{"scan:prowler:gcp-cis-5-0"},
		})
		Expect(err).To(MatchError(ContainSubstring("credentialMode must be ambient or configured")))
	})
})
