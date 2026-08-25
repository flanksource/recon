package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("provider contexts in the inventory", Ordered, Label("db"), func() {
	var (
		db  *dbtest.DB
		st  *store.Store
		ctx context.Context
	)

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_provider_contexts",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
		config := map[string]any{"provider": "gcp"}
		Expect(db.Gorm().Create(&models.EngineProfile{
			Kind: "scan", Engine: "prowler", Name: "gcp-cis-5-0",
			Config: models.JSON[map[string]any]{V: &config},
		}).Error).To(Succeed())

		for _, target := range []api.TargetDocument{
			{
				ID: "gcp-production", Kind: api.KindProviderContext,
				Provider: "gcp", CredentialMode: api.CredentialAmbient,
				Arguments: map[string]any{"project-ids": []any{"workload-prod-eu-02", "flanksource-prod"}},
				Class:     api.ClassProd, Profiles: []string{"scan:prowler:gcp-cis-5-0"}, Tags: []string{},
			},
			{
				ID: "github-production", Kind: api.KindProviderContext,
				Provider: "github", CredentialMode: api.CredentialConfigured,
				Arguments: map[string]any{"organizations": []any{"flanksource"}},
				Class:     api.ClassProd, Profiles: []string{"scan:prowler:github-cis"}, Tags: []string{},
			},
			{
				ID: "api", Host: "api.example.test", Kind: api.KindHost,
				Class: api.ClassProd, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
			},
		} {
			Expect(st.SaveTarget(ctx, target)).To(Succeed(), target.ID)
		}
	})

	It("resolves only contexts for the requested provider", func() {
		contexts, err := st.ProviderContexts(ctx, store.TargetOpts{}, "gcp")

		Expect(err).ToNot(HaveOccurred())
		Expect(contexts).To(Equal([]store.ProviderContext{{
			ID: "gcp-production", Provider: "gcp", CredentialMode: api.CredentialAmbient,
			Arguments: map[string]any{"project-ids": []any{"workload-prod-eu-02", "flanksource-prod"}},
			Class:     api.ClassProd,
		}}))
	})

	It("refuses an explicit context belonging to another provider", func() {
		_, err := st.ProviderContexts(ctx, store.TargetOpts{IDs: []string{"github-production"}}, "gcp")

		Expect(err).To(MatchError(ContainSubstring("github-production uses provider github, not gcp")))
	})

	It("never resolves a provider context as a network endpoint", func() {
		endpoints, err := st.Endpoints(ctx, store.TargetOpts{IDs: []string{"gcp-production"}})

		Expect(err).ToNot(HaveOccurred())
		Expect(endpoints).To(BeEmpty())
	})

	It("updates provider configuration atomically through the validation hook", func() {
		st.SetProviderContextValidator(func(_ context.Context, target api.TargetDocument) error {
			if target.Provider == "gcp" && target.Arguments["project-ids"] == nil {
				return fmt.Errorf("context schema requires project-ids")
			}
			return nil
		})
		DeferCleanup(func() { st.SetProviderContextValidator(nil) })

		mode := api.CredentialConfigured
		arguments := map[string]any{"project-ids": []any{"example-prod"}}
		updated, err := st.UpdateTarget(ctx, "gcp-production", api.TargetUpdate{
			CredentialMode: &mode, Arguments: &arguments,
			Curated: api.Curated{
				Class: api.ClassNonProd, Profiles: api.StringList{"scan:prowler:gcp-cis-5-0"},
				Tags: api.StringList{"changed"},
			},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(updated.CredentialMode).To(Equal(api.CredentialConfigured))
		Expect(updated.Arguments).To(Equal(arguments))
		Expect(updated.Tags).To(Equal([]string{"changed"}))

		empty := map[string]any{}
		_, err = st.UpdateTarget(ctx, "gcp-production", api.TargetUpdate{
			Arguments: &empty,
			Curated: api.Curated{
				Class: api.ClassProd, Profiles: api.StringList{"scan:prowler:gcp-cis-5-0"},
				Tags: api.StringList{"invalid"},
			},
		})
		Expect(err).To(MatchError(ContainSubstring("context schema requires project-ids")))

		stored, getErr := st.GetTarget(ctx, "gcp-production")
		Expect(getErr).ToNot(HaveOccurred())
		Expect(stored.Tags).To(Equal([]string{"changed"}), "the failed edit must roll back curation too")
		Expect(stored.Arguments).To(Equal(arguments))
	})

	It("refuses provider configuration on a host edit", func() {
		mode := api.CredentialAmbient
		_, err := st.UpdateTarget(ctx, "api", api.TargetUpdate{
			CredentialMode: &mode,
			Curated: api.Curated{
				Class: api.ClassProd, Profiles: api.StringList{"scan:nuclei:safe"}, Tags: api.StringList{},
			},
		})
		Expect(err).To(MatchError(ContainSubstring("host target api cannot have provider configuration")))
	})

	It("preserves, replaces, redacts, and clears credentials atomically", func() {
		curated := api.Curated{
			Class: api.ClassNonProd, Profiles: api.StringList{"scan:prowler:gcp-cis-5-0"},
			Tags: api.StringList{"changed"},
		}
		credentials := &api.ProviderCredentials{EnvVars: []api.CredentialEnvVar{{
			Name: "PROVIDER_TOKEN", Value: "stored-token",
		}}}
		updated, err := st.UpdateTarget(ctx, "gcp-production", api.TargetUpdate{
			Curated: curated, Credentials: credentials, CredentialsSet: true,
		})
		Expect(err).ToNot(HaveOccurred())
		body, err := json.Marshal(updated)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).ToNot(ContainSubstring("stored-token"))
		Expect(string(body)).To(ContainSubstring(`"configured":true`))

		contexts, err := st.ProviderContexts(ctx, store.TargetOpts{IDs: []string{"gcp-production"}}, "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(contexts).To(HaveLen(1))
		Expect(contexts[0].Credentials.EnvVars[0].ValueStatic).To(Equal("stored-token"))

		preservedMarker, err := st.UpdateTarget(ctx, "gcp-production", api.TargetUpdate{
			Curated: curated,
			Credentials: &api.ProviderCredentials{EnvVars: []api.CredentialEnvVar{{
				Name: "PROVIDER_TOKEN", Configured: true,
			}}}, CredentialsSet: true,
		})
		Expect(err).ToNot(HaveOccurred())
		body, err = json.Marshal(preservedMarker)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring(`"configured":true`))
		contexts, err = st.ProviderContexts(ctx, store.TargetOpts{IDs: []string{"gcp-production"}}, "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(contexts[0].Credentials.EnvVars[0].ValueStatic).To(Equal("stored-token"))

		preserved, err := st.UpdateTarget(ctx, "gcp-production", api.TargetUpdate{Curated: curated})
		Expect(err).ToNot(HaveOccurred())
		Expect(preserved.Credentials.EnvVars[0].Value).To(Equal("stored-token"))

		cleared, err := st.UpdateTarget(ctx, "gcp-production", api.TargetUpdate{
			Curated: curated, CredentialsSet: true,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(cleared.Credentials).To(BeNil())
		contexts, err = st.ProviderContexts(ctx, store.TargetOpts{IDs: []string{"gcp-production"}}, "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(contexts[0].Credentials).To(BeNil())
	})
})
