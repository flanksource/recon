package auth

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
)

func TestAuth(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Prowler auth policy")
}

var _ = Describe("Prowler auth policy", func() {
	It("covers exactly the selected providers", func() {
		Expect(Providers()).To(Equal([]string{
			"aws", "azure", "cloudflare", "gcp", "github", "googleworkspace",
			"image", "llm", "m365", "mongodbatlas", "vercel",
		}))
	})

	DescribeTable("declares native connection methods", func(provider, key, connectionType string, args map[string]any) {
		policy, ok := ForProvider(provider)
		Expect(ok).To(BeTrue())
		Expect(policy.Methods).To(HaveLen(1))
		Expect(policy.Methods[0].Connection).To(Equal(&Connection{Key: key, Type: connectionType}))
		Expect(policy.Methods[0].Arguments).To(Equal(args))
	},
		Entry("AWS", "aws", "aws", "aws", map[string]any{}),
		Entry("Azure", "azure", "azure", "azure", map[string]any{"sp-env-auth": true}),
		Entry("GCP", "gcp", "gcp", "google_cloud", map[string]any{}),
	)

	It("supports Azure connections and certificate content for Microsoft 365", func() {
		policy, ok := ForProvider("m365")
		Expect(ok).To(BeTrue())
		Expect(policy.Methods).To(HaveLen(2))
		Expect(policy.Methods[0].Connection).To(Equal(&Connection{Key: "azure", Type: "azure"}))
		Expect(policy.Methods[0].Arguments).To(Equal(map[string]any{"sp-env-auth": true}))
		Expect(policy.Methods[1]).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"EnvVars":          Equal([]EnvVar{{Name: "AZURE_CLIENT_ID", Title: "Client ID"}, {Name: "M365_CERTIFICATE_CONTENT", Title: "Certificate content"}}),
			"RequiredSettings": Equal([]string{"tenant-id"}),
			"Arguments":        Equal(map[string]any{"certificate-auth": true}),
		}))
	})

	DescribeTable("declares environment authentication alternatives", func(provider string, methodVariables [][]string) {
		policy, ok := ForProvider(provider)
		Expect(ok).To(BeTrue())
		actual := make([][]string, 0, len(policy.Methods))
		for _, method := range policy.Methods {
			names := make([]string, 0, len(method.EnvVars))
			for _, variable := range method.EnvVars {
				names = append(names, variable.Name)
			}
			actual = append(actual, names)
		}
		Expect(actual).To(Equal(methodVariables))
	},
		Entry("Cloudflare", "cloudflare", [][]string{{"CLOUDFLARE_API_TOKEN"}, {"CLOUDFLARE_API_KEY"}}),
		Entry("GitHub", "github", [][]string{{"GITHUB_PERSONAL_ACCESS_TOKEN"}, {"GITHUB_OAUTH_APP_TOKEN"}, {"GITHUB_APP_KEY"}}),
		Entry("Google Workspace", "googleworkspace", [][]string{{"GOOGLEWORKSPACE_CREDENTIALS_CONTENT"}}),
		Entry("Image", "image", [][]string{{"REGISTRY_TOKEN"}, {"REGISTRY_PASSWORD"}}),
		Entry("LLM", "llm", [][]string{{"OPENAI_API_KEY"}}),
		Entry("MongoDB Atlas", "mongodbatlas", [][]string{{"ATLAS_PRIVATE_KEY"}}),
		Entry("Vercel", "vercel", [][]string{{"VERCEL_TOKEN"}}),
	)

	It("declares non-secret environment settings and complete ambient allowlists", func() {
		cloudflare, _ := ForProvider("cloudflare")
		Expect(cloudflare.Settings).To(Equal([]Setting{{
			Key: "api-email", Environment: "CLOUDFLARE_API_EMAIL", Title: "API email",
		}}))
		Expect(cloudflare.Methods[1].RequiredSettings).To(Equal([]string{"api-email"}))
		Expect(cloudflare.Ambient).To(Equal([]string{
			"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_API_EMAIL",
		}))

		workspace, _ := ForProvider("googleworkspace")
		Expect(workspace.Settings).To(Equal([]Setting{{
			Key: "delegated-user", Environment: "GOOGLEWORKSPACE_DELEGATED_USER", Title: "Delegated user", Required: true,
		}}))
	})
})
