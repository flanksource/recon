package entities

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/flanksource/commons-db/connection"
	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	enginecatalog "github.com/flanksource/recon/internal/engines"
	_ "github.com/flanksource/recon/internal/engines/all" // populate the registry
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("provider context schema validation", Ordered, Label("db"), func() {
	var (
		st  *store.Store
		ctx context.Context
	)

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}
		db := dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_entity_provider_context_validation",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		(&Registry{}).SetStore(st)
		ctx = context.Background()
		for _, profile := range []models.EngineProfile{
			{Kind: "scan", Engine: "prowler", Name: "gcp-context", Config: models.JSON[map[string]any]{V: &map[string]any{"provider": "gcp"}}},
			{Kind: "scan", Engine: "prowler", Name: "aws-context", Config: models.JSON[map[string]any]{V: &map[string]any{"provider": "aws"}}},
			{Kind: "scan", Engine: "prowler", Name: "cloudflare-context", Config: models.JSON[map[string]any]{V: &map[string]any{"provider": "cloudflare"}}},
			{Kind: "scan", Engine: "nuclei", Name: "safe", Config: models.JSON[map[string]any]{V: &map[string]any{}}},
			{Kind: "scan", Engine: "trivy", Name: "image", Config: models.JSON[map[string]any]{V: &map[string]any{
				"provider": "container-image", "scanners": []any{"vuln"},
			}}},
		} {
			Expect(db.Gorm().Create(&profile).Error).To(Succeed())
		}
	})

	It("uses the registered provider schema without affecting host targets", func() {
		contextTarget := api.TargetDocument{
			ID: "gcp-workloads", Kind: api.KindProviderContext, Provider: "gcp",
			CredentialMode: api.CredentialAmbient,
			Arguments:      map[string]any{"project-ids": []any{"workload-prod-eu-02", "flanksource-prod"}},
			Class:          api.ClassProd, Profiles: []string{"scan:prowler:gcp-context"}, Tags: []string{},
		}
		Expect(st.SaveTarget(ctx, contextTarget)).To(Succeed())

		invalid := contextTarget
		invalid.ID = "gcp-invalid"
		invalid.Arguments = map[string]any{"not-a-prowler-argument": true}
		Expect(st.SaveTarget(ctx, invalid)).To(MatchError(ContainSubstring("not-a-prowler-argument")))

		host := api.TargetDocument{
			ID: "api.example.test", Host: "api.example.test", Kind: api.KindHost,
			Class: api.ClassProd, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
		}
		Expect(st.SaveTarget(ctx, host)).To(Succeed())
	})

	It("fails when no engine claims the provider", func() {
		target := api.TargetDocument{
			ID: "unknown-provider", Kind: api.KindProviderContext, Provider: "unknown",
			CredentialMode: api.CredentialAmbient, Arguments: map[string]any{},
			Class: api.ClassProd, Profiles: []string{"scan:prowler:gcp-context"}, Tags: []string{},
		}
		Expect(st.SaveTarget(ctx, target)).To(MatchError(ContainSubstring(
			"no scan engine defines context options for provider \"unknown\"")))
	})

	// The provider decides which engine validates the target. Trivy's providers
	// are artifacts rather than cloud accounts, so this is also the check that
	// a second provider-backed engine can exist at all.
	It("validates a target against the engine that owns its provider", func() {
		target := api.TargetDocument{
			ID: "api-image", Kind: api.KindProviderContext, Provider: "container-image",
			CredentialMode: api.CredentialAmbient,
			Arguments:      map[string]any{"image": "ghcr.io/acme/api@sha256:" + strings.Repeat("ab", 32)},
			Class:          api.ClassProd, Profiles: []string{"scan:trivy:image"}, Tags: []string{},
		}
		Expect(st.SaveTarget(ctx, target)).To(Succeed())

		// Trivy's schema, not prowler's: prowler has no "image" argument and
		// would have rejected a valid target.
		unknown := target
		unknown.ID = "api-image-bad-argument"
		unknown.Arguments = map[string]any{"image": "ghcr.io/acme/api:1.4", "project-ids": []any{"prod"}}
		Expect(st.SaveTarget(ctx, unknown)).To(MatchError(ContainSubstring("project-ids")))

		// Credentials belong to the environment trivy runs in, so a target
		// carrying its own is refused rather than scanned unauthenticated.
		credentialed := target
		credentialed.ID = "api-image-credentialed"
		credentialed.CredentialMode = api.CredentialConfigured
		credentialed.Credentials = &api.ProviderCredentials{
			EnvVars: []api.CredentialEnvVar{{Name: "TRIVY_PASSWORD", Value: "inline"}},
		}
		Expect(st.SaveTarget(ctx, credentialed)).To(MatchError(ContainSubstring(
			"does not accept credentials")))
	})

	It("refuses a profile written for another engine's provider", func() {
		target := api.TargetDocument{
			ID: "api-image-gcp-profile", Kind: api.KindProviderContext, Provider: "container-image",
			CredentialMode: api.CredentialAmbient,
			Arguments:      map[string]any{"image": "ghcr.io/acme/api:1.4"},
			Class:          api.ClassProd, Profiles: []string{"scan:prowler:gcp-context"}, Tags: []string{},
		}
		Expect(st.SaveTarget(ctx, target)).To(MatchError(ContainSubstring(
			"uses provider gcp, not container-image")))
	})

	It("enforces credential selector semantics before persistence", func() {
		ambient := api.TargetDocument{
			ID: "gcp-ambient-selector", Kind: api.KindProviderContext, Provider: "gcp",
			CredentialMode: api.CredentialAmbient,
			Arguments:      map[string]any{"credentials-file": "credentials/gcp.json"},
			Class:          api.ClassProd, Profiles: []string{"scan:prowler:gcp-context"}, Tags: []string{},
		}
		Expect(st.SaveTarget(ctx, ambient)).To(MatchError(ContainSubstring(
			"credential selector \"credentials-file\" is not allowed in ambient credential mode")))

		configured := ambient
		configured.ID = "gcp-configured-no-selector"
		configured.CredentialMode = api.CredentialConfigured
		configured.Arguments = map[string]any{"project-ids": []any{"workload-prod-eu-02"}}
		Expect(st.SaveTarget(ctx, configured)).To(MatchError(ContainSubstring(
			"configured credential mode requires credentials or an explicit credential selector")))

		configured.ID = "gcp-configured"
		configured.Arguments["credentials-file"] = "credentials/gcp.json"
		Expect(st.SaveTarget(ctx, configured)).To(Succeed())
	})

	It("enforces the Cloudflare credential schema and redacts API reads", func() {
		target := api.TargetDocument{
			ID: "cloudflare-production", Kind: api.KindProviderContext, Provider: "cloudflare",
			CredentialMode: api.CredentialConfigured, Arguments: map[string]any{},
			Credentials: &api.ProviderCredentials{EnvVars: []api.CredentialEnvVar{{
				Name: "CLOUDFLARE_API_TOKEN", Value: "inline-token",
			}}},
			Class: api.ClassProd, Profiles: []string{"scan:prowler:cloudflare-context"}, Tags: []string{},
		}
		Expect(st.SaveTarget(ctx, target)).To(Succeed())

		read, err := st.GetTarget(ctx, target.ID)
		Expect(err).ToNot(HaveOccurred())
		body, err := json.Marshal(read)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).ToNot(ContainSubstring("inline-token"))
		Expect(string(body)).To(ContainSubstring(`"configured":true`))

		ambient := target
		ambient.ID = "cloudflare-ambient-secret"
		ambient.CredentialMode = api.CredentialAmbient
		Expect(st.SaveTarget(ctx, ambient)).To(MatchError(ContainSubstring(
			"credentials are not allowed in ambient credential mode")))

		missing := target
		missing.ID = "cloudflare-configured-empty"
		missing.Credentials = nil
		Expect(st.SaveTarget(ctx, missing)).To(MatchError(ContainSubstring(
			"configured credential mode requires credentials")))

		wrongName := target
		wrongName.ID = "cloudflare-wrong-name"
		wrongName.Credentials.EnvVars[0].Name = "CLOUDFLARE_EMAIL"
		Expect(st.SaveTarget(ctx, wrongName)).To(MatchError(ContainSubstring("CLOUDFLARE_API_TOKEN")))

		connections := target
		connections.ID = "cloudflare-connections"
		connections.Credentials = &api.ProviderCredentials{
			Connections: &connection.ExecConnections{ServiceAccount: true},
		}
		Expect(st.SaveTarget(ctx, connections)).To(MatchError(ContainSubstring(
			"additional properties 'connections' not allowed")))
	})

	It("requires every selected profile to support the target provider context", func() {
		target := api.TargetDocument{
			ID: "gcp-nuclei", Kind: api.KindProviderContext, Provider: "gcp",
			CredentialMode: api.CredentialAmbient,
			Arguments:      map[string]any{"project-ids": []any{"workload-prod-eu-02"}},
			Class:          api.ClassProd, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
		}
		Expect(st.SaveTarget(ctx, target)).To(MatchError(ContainSubstring(
			"profile scan:nuclei:safe has no context schema")))

		target.ID = "gcp-aws-profile"
		target.Profiles = []string{"scan:prowler:aws-context"}
		Expect(st.SaveTarget(ctx, target)).To(MatchError(ContainSubstring(
			"profile scan:prowler:aws-context uses provider aws, not gcp")))
	})
})

var _ = Describe("provider context validation contract", func() {
	It("fails when the selected provider has no context schema", func() {
		spec := enginecatalog.Spec{Name: "prowler", Options: enginecatalog.OptionCatalog{
			Discriminator: "provider",
			Variants:      []enginecatalog.OptionVariant{{ID: "gcp"}},
		}}
		target := api.TargetDocument{
			Kind: api.KindProviderContext, Provider: "gcp",
			CredentialMode: api.CredentialAmbient, Arguments: map[string]any{},
		}

		Expect(validateProviderContextSpec(spec, target)).To(MatchError("prowler provider gcp has no context schema"))
	})

	It("names the engine whose schema refused the target", func() {
		// The message used to say "prowler" whichever engine owned the provider,
		// which pointed whoever read it at the wrong schema.
		contextSchema := enginecatalog.JSONSchema{
			"type": "object", "properties": map[string]any{}, "additionalProperties": false,
		}
		spec := enginecatalog.Spec{Name: "trivy", Options: enginecatalog.OptionCatalog{
			Discriminator: "provider",
			Variants: []enginecatalog.OptionVariant{{
				ID: "container-image", ContextSchema: &contextSchema,
			}},
		}}
		target := api.TargetDocument{
			Kind: api.KindProviderContext, Provider: "container-image",
			CredentialMode: api.CredentialAmbient,
			Arguments:      map[string]any{"not-an-option": true},
		}

		Expect(validateProviderContextSpec(spec, target)).To(MatchError(
			ContainSubstring("trivy provider container-image context schema")))
	})

	It("refuses credentials for a provider that declares none rather than requiring a schema", func() {
		// An engine whose tools read their credentials from the environment
		// declares no credential schema. That is a statement — it takes none —
		// and a target that attaches some is refused rather than scanned
		// unauthenticated.
		contextSchema := enginecatalog.JSONSchema{
			"type": "object", "properties": map[string]any{}, "additionalProperties": false,
		}
		spec := enginecatalog.Spec{Name: "trivy", Options: enginecatalog.OptionCatalog{
			Discriminator: "provider",
			Variants: []enginecatalog.OptionVariant{{
				ID: "container-image", ContextSchema: &contextSchema,
			}},
		}}
		target := api.TargetDocument{
			Kind: api.KindProviderContext, Provider: "container-image",
			CredentialMode: api.CredentialAmbient, Arguments: map[string]any{},
		}

		Expect(validateProviderContextSpec(spec, target)).To(Succeed())

		withCredentials := target
		withCredentials.CredentialMode = api.CredentialConfigured
		withCredentials.Credentials = &api.ProviderCredentials{
			EnvVars: []api.CredentialEnvVar{{Name: "TRIVY_PASSWORD", Value: "inline"}},
		}
		Expect(validateProviderContextSpec(spec, withCredentials)).To(MatchError(
			ContainSubstring("does not accept credentials")))
	})

	It("never persists a sensitive context property even when a schema exposes it", func() {
		contextSchema := enginecatalog.JSONSchema{
			"type": "object",
			"properties": map[string]any{
				"direct-secret": enginecatalog.JSONSchema{
					"type": "string", "writeOnly": true, "x-sensitive": true,
				},
			},
			"additionalProperties": false,
		}
		credentialSchema := enginecatalog.JSONSchema{
			"type": "object", "properties": map[string]any{}, "additionalProperties": false,
		}
		spec := enginecatalog.Spec{Name: "prowler", Options: enginecatalog.OptionCatalog{
			Discriminator: "provider",
			Variants: []enginecatalog.OptionVariant{{
				ID: "gcp", ContextSchema: &contextSchema, CredentialSchema: &credentialSchema,
			}},
		}}
		target := api.TargetDocument{
			Kind: api.KindProviderContext, Provider: "gcp",
			CredentialMode: api.CredentialConfigured,
			Arguments:      map[string]any{"direct-secret": "do-not-store"},
		}

		Expect(validateProviderContextSpec(spec, target)).To(MatchError(
			"provider context argument \"direct-secret\" is sensitive and cannot be persisted"))
	})
})
