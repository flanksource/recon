package prowler

import (
	"github.com/flanksource/commons-db/connection"
	"github.com/flanksource/commons-db/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	credentialstore "github.com/flanksource/recon/internal/credentials"
)

var _ = Describe("Prowler provider execution", func() {
	It("limits ambient passthrough to Cloudflare's supported credential variables", func() {
		cloudflare, err := providerShellExec(providerContext{
			ID: "cloudflare-prod", Provider: "cloudflare", CredentialMode: api.CredentialAmbient,
		}, "/scan", "/scan/context")
		Expect(err).ToNot(HaveOccurred())
		Expect(cloudflare.PassthroughEnv).To(Equal([]string{
			"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_API_EMAIL",
		}))

		gcp, err := providerShellExec(providerContext{
			ID: "gcp-prod", Provider: "gcp", CredentialMode: api.CredentialAmbient,
		}, "/scan", "/scan/context")
		Expect(err).ToNot(HaveOccurred())
		Expect(gcp.PassthroughEnv).To(BeEmpty())
	})

	It("copies configured EnvVars and ExecConnections into an isolated shell request", func() {
		stored := &credentialstore.ProviderCredentials{
			EnvVars: []types.EnvVar{{Name: "PROVIDER_TOKEN", ValueStatic: "runtime-value"}},
			Connections: &connection.ExecConnections{AWS: &connection.AWSConnection{
				Region: "af-south-1",
			}},
		}
		execution, err := providerShellExec(providerContext{
			ID: "aws-prod", Provider: "aws", CredentialMode: api.CredentialConfigured,
			Credentials: stored,
		}, "/scan", "/scan/context")
		Expect(err).ToNot(HaveOccurred())
		Expect(execution.PassthroughEnv).To(BeEmpty())
		Expect(execution.EnvVars).To(Equal(stored.EnvVars))
		Expect(execution.Connections).To(Equal(*stored.Connections))

		stored.EnvVars[0].ValueStatic = "changed"
		stored.Connections.AWS.Region = "changed"
		Expect(execution.EnvVars[0].ValueStatic).To(Equal("runtime-value"))
		Expect(execution.Connections.AWS.Region).To(Equal("af-south-1"))
	})

	DescribeTable("rejects ambient inheritance switches in configured mode", func(connections connection.ExecConnections) {
		_, err := providerShellExec(providerContext{
			ID: "configured", Provider: "aws", CredentialMode: api.CredentialConfigured,
			Credentials: &credentialstore.ProviderCredentials{Connections: &connections},
		}, "/scan", "/scan/context")
		Expect(err).To(MatchError(ContainSubstring("cannot inherit ambient credentials")))
	},
		Entry("EKS pod identity", connection.ExecConnections{EKSPodIdentity: true}),
		Entry("Kubernetes service account", connection.ExecConnections{ServiceAccount: true}),
	)
})
