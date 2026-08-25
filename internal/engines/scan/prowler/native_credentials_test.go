package prowler

import (
	"context"
	"os"

	"github.com/flanksource/commons-db/connection"
	dbcontext "github.com/flanksource/commons-db/context"
	commonsmodels "github.com/flanksource/commons-db/models"
	"github.com/flanksource/commons-db/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	credentialstore "github.com/flanksource/recon/internal/credentials"
)

var _ = Describe("Prowler native credentials", func() {
	It("materializes an isolated AWS credential file", func() {
		ctx := connectionContext(commonsmodels.Connection{
			Name: "prod-aws", Type: "aws", Username: "access-key", Password: "secret-key",
			Properties: types.JSONStringMap{"region": "af-south-1"},
		})
		prepared, err := prepareNativeCredentials(ctx, nativeSubject("aws", &connection.ExecConnections{
			AWS: &connection.AWSConnection{ConnectionName: "connection://prod-aws"},
		}), GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		Expect(prepared.Native).To(BeTrue())
		environment := environmentValues(prepared.EnvVars)
		Expect(environment).To(HaveKeyWithValue("AWS_DEFAULT_REGION", "af-south-1"))
		Expect(environment).To(HaveKeyWithValue("AWS_ACCESS_KEY_ID", "access-key"))
		path := environment["AWS_SHARED_CREDENTIALS_FILE"]
		info, err := os.Stat(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(info.Mode().Perm()).To(Equal(os.FileMode(0o600)))
		content, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(content)).To(ContainSubstring("aws_secret_access_key = secret-key"))
		Expect(prepared.Cleanup()).To(Succeed())
		Expect(path).NotTo(BeAnExistingFile())
	})

	It("projects Azure connections directly to service-principal environment variables", func() {
		ctx := connectionContext(commonsmodels.Connection{
			Name: "prod-azure", Type: "azure", Username: "client-id", Password: "client-secret",
			Properties: types.JSONStringMap{"tenant": "tenant-id"},
		})
		prepared, err := prepareNativeCredentials(ctx, nativeSubject("azure", &connection.ExecConnections{
			Azure: &connection.AzureConnection{ConnectionName: "connection://prod-azure"},
		}), GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		Expect(environmentValues(prepared.EnvVars)).To(Equal(map[string]string{
			"AZURE_CLIENT_ID": "client-id", "AZURE_CLIENT_SECRET": "client-secret", "AZURE_TENANT_ID": "tenant-id",
		}))
	})

	It("materializes GCP service-account JSON without invoking gcloud", func() {
		credentials := `{ "client_email": "scanner@example.test", "private_key": "secret" }`
		ctx := connectionContext(commonsmodels.Connection{Name: "prod-gcp", Type: "google_cloud", Certificate: credentials})
		prepared, err := prepareNativeCredentials(ctx, nativeSubject("gcp", &connection.ExecConnections{
			GCP: &connection.GCPConnection{ConnectionName: "connection://prod-gcp"},
		}), GinkgoT().TempDir())
		Expect(err).NotTo(HaveOccurred())
		path := environmentValues(prepared.EnvVars)["GOOGLE_APPLICATION_CREDENTIALS"]
		content, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(content)).To(Equal(`{"client_email":"scanner@example.test","private_key":"secret"}`))
		Expect(prepared.Cleanup()).To(Succeed())
	})
})

func connectionContext(model commonsmodels.Connection) dbcontext.Context {
	return dbcontext.NewContext(context.Background()).WithConnectionResolver(func(reference string) (*commonsmodels.Connection, error) {
		Expect(reference).To(Equal("connection://" + model.Name))
		copy := model
		return &copy, nil
	})
}

func nativeSubject(provider string, connections *connection.ExecConnections) providerContext {
	return providerContext{
		ID: "prod-" + provider, Provider: provider, CredentialMode: api.CredentialConfigured,
		Arguments: map[string]any{}, Credentials: &credentialstore.ProviderCredentials{Connections: connections},
	}
}

func environmentValues(values []types.EnvVar) map[string]string {
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[value.Name] = value.ValueStatic
	}
	return result
}
