package api_test

import (
	"encoding/json"

	"github.com/flanksource/commons-db/connection"
	"github.com/flanksource/commons-db/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("provider credentials wire contract", func() {
	configuredTarget := func(credentials any) map[string]any {
		return map[string]any{
			"id": "cloudflare-production", "kind": "provider-context", "provider": "cloudflare",
			"credentialMode": "configured", "credentials": credentials,
			"arguments": map[string]any{}, "class": "prod",
			"profiles": []any{"scan:prowler:cloudflare-cis"}, "tags": []any{},
		}
	}

	It("decodes EnvVar-compatible credentials on create", func() {
		target, err := api.TargetFrom(configuredTarget(map[string]any{
			"envVars": []any{map[string]any{
				"name": "CLOUDFLARE_API_TOKEN", "value": "inline-token",
			}},
		}))

		Expect(err).ToNot(HaveOccurred())
		Expect(target.Credentials).To(Equal(&api.ProviderCredentials{
			EnvVars: []api.CredentialEnvVar{{Name: "CLOUDFLARE_API_TOKEN", Value: "inline-token"}},
		}))
	})

	It("redacts inline values while preserving references", func() {
		secretName, secretKey := "prowler", "cloudflare-token"
		body, err := json.Marshal(api.TargetDocument{
			ID: "cloudflare-production", Kind: api.KindProviderContext, Provider: "cloudflare",
			CredentialMode: api.CredentialConfigured, Arguments: map[string]any{},
			Credentials: &api.ProviderCredentials{EnvVars: []api.CredentialEnvVar{
				{Name: "CLOUDFLARE_API_TOKEN", Value: "inline-token"},
				{Name: "CLOUDFLARE_API_TOKEN_REF", ValueFrom: &types.EnvVarSource{
					SecretKeyRef: &types.SecretKeySelector{
						LocalObjectReference: types.LocalObjectReference{Name: secretName}, Key: secretKey,
					},
				}},
			}},
			Class: api.ClassProd, Profiles: []string{"scan:prowler:cloudflare-cis"}, Tags: []string{},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).ToNot(ContainSubstring("inline-token"))
		Expect(body).To(MatchJSON(`{
			"$schema":"../target.schema.json","version":3,"id":"cloudflare-production",
			"kind":"provider-context","provider":"cloudflare","credentialMode":"configured",
			"credentials":{"envVars":[
				{"name":"CLOUDFLARE_API_TOKEN","configured":true},
				{"name":"CLOUDFLARE_API_TOKEN_REF","valueFrom":{"secretKeyRef":{"name":"prowler","key":"cloudflare-token"}}}
			]},"class":"prod","profiles":["scan:prowler:cloudflare-cis"],"tags":[]
		}`))
	})

	It("redacts inline values from every nested execution connection", func() {
		credentials := func(value string) *types.EnvVar {
			return &types.EnvVar{ValueStatic: value}
		}
		body, err := json.Marshal(api.ProviderCredentials{Connections: &connection.ExecConnections{
			AWS: &connection.AWSConnection{AccessKey: types.EnvVar{ValueStatic: "top-aws"}},
			GCP: &connection.GCPConnection{Credentials: credentials("top-gcp")},
			Azure: &connection.AzureConnection{
				ClientID: credentials("top-azure-id"), ClientSecret: credentials("top-azure-secret"),
			},
			Kubernetes: &connection.KubernetesConnection{
				KubeconfigConnection: connection.KubeconfigConnection{Kubeconfig: credentials("kube-secret-content")},
				EKS: &connection.EKSConnection{AWSConnection: connection.AWSConnection{
					SecretKey: types.EnvVar{ValueStatic: "nested-eks"},
				}},
				GKE: &connection.GKEConnection{GCPConnection: connection.GCPConnection{
					Credentials: credentials("nested-gke"),
				}},
				CNRM: &connection.CNRMConnection{GKE: connection.GKEConnection{
					GCPConnection: connection.GCPConnection{Credentials: credentials("nested-cnrm")},
				}},
			},
		}})

		Expect(err).ToNot(HaveOccurred())
		for _, secret := range []string{
			"top-aws", "top-gcp", "top-azure-id", "top-azure-secret",
			"kube-secret-content", "nested-eks", "nested-gke", "nested-cnrm",
		} {
			Expect(string(body)).ToNot(ContainSubstring(secret))
		}
		Expect(string(body)).To(ContainSubstring(`"configured":true`))
	})

	It("distinguishes omitted, null, and replacement credentials on PATCH", func() {
		omitted, err := api.TargetUpdateFrom(map[string]any{
			"class": "prod", "profiles": []any{"scan:prowler:cloudflare-cis"}, "tags": []any{},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(omitted.CredentialsSet).To(BeFalse())

		cleared, err := api.TargetUpdateFrom(map[string]any{
			"credentials": nil, "class": "prod",
			"profiles": []any{"scan:prowler:cloudflare-cis"}, "tags": []any{},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(cleared.CredentialsSet).To(BeTrue())
		Expect(cleared.Credentials).To(BeNil())

		replaced, err := api.TargetUpdateFrom(map[string]any{
			"credentials": map[string]any{"envVars": []any{map[string]any{
				"name": "CLOUDFLARE_API_TOKEN", "value": "replacement",
			}}},
			"class": "prod", "profiles": []any{"scan:prowler:cloudflare-cis"}, "tags": []any{},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(replaced.CredentialsSet).To(BeTrue())
		Expect(replaced.Credentials).To(Equal(&api.ProviderCredentials{
			EnvVars: []api.CredentialEnvVar{{Name: "CLOUDFLARE_API_TOKEN", Value: "replacement"}},
		}))
	})

	It("accepts configured markers only on updates", func() {
		update, err := api.TargetUpdateFrom(map[string]any{
			"credentials": map[string]any{"envVars": []any{map[string]any{
				"name": "CLOUDFLARE_API_TOKEN", "configured": true,
			}}},
			"class": "prod", "profiles": []any{"scan:prowler:cloudflare-cis"}, "tags": []any{},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(update.Credentials.EnvVars).To(Equal([]api.CredentialEnvVar{{
			Name: "CLOUDFLARE_API_TOKEN", Configured: true,
		}}))

		_, err = api.TargetFrom(configuredTarget(map[string]any{
			"envVars": []any{map[string]any{
				"name": "CLOUDFLARE_API_TOKEN", "configured": true,
			}},
		}))

		Expect(err).To(MatchError(ContainSubstring("configured marker is not allowed when creating")))
	})
})
