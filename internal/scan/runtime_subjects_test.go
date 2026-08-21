package scan

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/flanksource/commons-db/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	credentialstore "github.com/flanksource/recon/internal/credentials"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("scan runtime subjects", func() {
	It("writes sanitized provider context evidence as JSONL", func() {
		dir := GinkgoT().TempDir()
		credentials := &credentialstore.ProviderCredentials{EnvVars: []types.EnvVar{{
			Name: "PROVIDER_TOKEN", ValueStatic: "runtime-value",
		}}}
		contexts := []store.ProviderContext{
			{
				ID: "gcp-production", Provider: "gcp", CredentialMode: api.CredentialAmbient,
				Arguments: map[string]any{"project-ids": []any{"example-prod"}, "skip-api-check": true},
				Class:     api.ClassProd,
			},
			{
				ID: "gcp-development", Provider: "gcp", CredentialMode: api.CredentialConfigured,
				Arguments: map[string]any{"project-ids": []any{"example-dev"}}, Class: api.ClassNonProd,
				Credentials: credentials,
			},
		}

		path, err := writeSubjects(dir, resolvedSubjects{ProviderContexts: contexts})
		Expect(err).ToNot(HaveOccurred())
		body, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		Expect(lines).To(HaveLen(2))
		Expect(string(body)).ToNot(ContainSubstring("credentials"))
		Expect(string(body)).ToNot(ContainSubstring("runtime-value"))
		for index, line := range lines {
			var decoded store.ProviderContext
			Expect(json.Unmarshal([]byte(line), &decoded)).To(Succeed())
			expected := contexts[index]
			expected.Credentials = nil
			Expect(decoded).To(Equal(expected))
		}

		Expect(engineProviderContexts(contexts)).To(Equal([]engines.ProviderContext{
			{
				ID: "gcp-production", Provider: "gcp", CredentialMode: api.CredentialAmbient,
				Arguments: map[string]any{"project-ids": []any{"example-prod"}, "skip-api-check": true},
				Class:     api.ClassProd,
			},
			{
				ID: "gcp-development", Provider: "gcp", CredentialMode: api.CredentialConfigured,
				Arguments: map[string]any{"project-ids": []any{"example-dev"}}, Class: api.ClassNonProd,
				Credentials: credentials,
			},
		}))
	})

	It("keeps endpoint input rendering byte-for-byte unchanged", func() {
		dir := GinkgoT().TempDir()
		path, err := writeSubjects(dir, resolvedSubjects{Endpoints: []store.Endpoint{
			{URL: "https://example.test"},
			{URL: "ssh://192.0.2.10:22"},
		}})
		Expect(err).ToNot(HaveOccurred())
		Expect(os.ReadFile(path)).To(BeEquivalentTo("https://example.test\nssh://192.0.2.10:22\n"))
	})

	It("refuses an empty subject set", func() {
		_, err := writeSubjects(GinkgoT().TempDir(), resolvedSubjects{})
		Expect(err).To(MatchError(ContainSubstring("empty targets")))
	})
})
