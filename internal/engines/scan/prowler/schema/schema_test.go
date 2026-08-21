package schema_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing/fstest"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

var _ = Describe("generated Prowler provider schemas", func() {
	It("embeds all pinned provider schemas and normalized argv metadata", func() {
		registry, err := schema.Embedded()
		Expect(err).NotTo(HaveOccurred())
		Expect(registry.ProviderIDs()).To(HaveLen(23))

		arguments, err := schema.ArgumentCatalogue()
		Expect(err).NotTo(HaveOccurred())
		Expect(arguments.Providers).To(HaveLen(23))

		options := registry.OptionCatalog()
		Expect(options.Variants).To(HaveLen(23))
		Expect(options.Validate()).To(Succeed())

		components, err := schema.OpenAPIComponents()
		Expect(err).NotTo(HaveOccurred())
		Expect(components).To(HaveLen(92))
		properties := components["ProwlerGCPProfileOptions"]["properties"].(engines.JSONSchema)
		providerProperty := properties["provider"].(engines.JSONSchema)
		Expect(providerProperty).NotTo(HaveKey("const"))
		Expect(providerProperty["enum"]).To(Equal([]any{"gcp"}))
		credential := components["ProwlerCloudflareCredential"]
		credentialProperties := credential["properties"].(engines.JSONSchema)
		envVars := credentialProperties["envVars"].(engines.JSONSchema)
		item := envVars["items"].(engines.JSONSchema)
		itemProperties := item["properties"].(engines.JSONSchema)
		name := itemProperties["name"].(engines.JSONSchema)
		Expect(name).NotTo(HaveKey("const"))
		Expect(name["enum"]).To(Equal([]any{"CLOUDFLARE_API_TOKEN"}))
	})

	It("exposes only the approved Cloudflare credential policy", func() {
		registry, err := schema.Embedded()
		Expect(err).NotTo(HaveOccurred())

		cloudflare, ok := registry.Provider("cloudflare")
		Expect(ok).To(BeTrue())
		Expect(cloudflare.Credential.Properties).To(SatisfyAll(HaveLen(1), HaveKey("envVars")))
		envVars := cloudflare.Credential.Properties["envVars"]
		Expect(envVars.Items.Properties["name"].Const).To(Equal("CLOUDFLARE_API_TOKEN"))
		Expect(envVars.Items.Properties["value"].WriteOnly).To(BeTrue())
		Expect(envVars.Items.Properties["configured"].ReadOnly).To(BeTrue())
		Expect(envVars.Items.Properties["valueFrom"].Properties).NotTo(HaveKey("serviceAccount"))

		gcp, ok := registry.Provider("gcp")
		Expect(ok).To(BeTrue())
		Expect(gcp.Credential.Properties).To(BeEmpty())

		options := registry.OptionCatalog()
		variant := options.Variants[providerIndex(registry.ProviderIDs(), "cloudflare")]
		Expect(variant.CredentialSchema).NotTo(BeNil())
		Expect(variant.CredentialSchemaRef).To(Equal("#/components/schemas/ProwlerCloudflareCredential"))
		Expect(options.ValidateCredentials(
			map[string]any{"provider": "cloudflare"},
			cloudflareCredential(map[string]any{"valueFrom": map[string]any{"onePassword": "op://vault/item/field"}}),
		)).To(Succeed())
		for _, value := range []map[string]any{
			{"value": "example"},
			{"valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": "scanner", "key": "api-token"}}},
			{"valueFrom": map[string]any{"configMapKeyRef": map[string]any{"name": "scanner", "key": "api-token"}}},
			{"valueFrom": map[string]any{"helmRef": map[string]any{"name": "scanner", "key": "$.credentials.token"}}},
			{"valueFrom": map[string]any{"onePassword": "op://vault/item/field"}},
		} {
			Expect(options.ValidateCredentials(
				map[string]any{"provider": "cloudflare"}, cloudflareCredential(value),
			)).To(Succeed())
		}
		Expect(options.ValidateCredentials(
			map[string]any{"provider": "cloudflare"},
			map[string]any{"connections": map[string]any{}},
		)).To(MatchError(ContainSubstring("additional properties 'connections' not allowed")))
		Expect(options.ValidateCredentials(
			map[string]any{"provider": "cloudflare"},
			cloudflareCredential(map[string]any{"valueFrom": map[string]any{"serviceAccount": "scanner"}}),
		)).To(MatchError(ContainSubstring("additional properties 'serviceAccount' not allowed")))
		Expect(options.ValidateCredentials(
			map[string]any{"provider": "cloudflare"},
			map[string]any{"envVars": []any{
				map[string]any{"name": "CLOUDFLARE_API_TOKEN", "value": "first"},
				map[string]any{"name": "CLOUDFLARE_API_TOKEN", "value": "second"},
			}},
		)).To(MatchError(ContainSubstring("maxItems: got 2, want 1")))
		Expect(options.ValidateCredentials(
			map[string]any{"provider": "cloudflare"},
			cloudflareCredential(map[string]any{
				"value": "example", "valueFrom": map[string]any{"onePassword": "op://vault/item/field"},
			}),
		)).To(MatchError(ContainSubstring("'oneOf' failed")))
	})

	It("keeps credentials out of persistable schemas", func() {
		registry, err := schema.Embedded()
		Expect(err).NotTo(HaveOccurred())
		github, ok := registry.Provider("github")
		Expect(ok).To(BeTrue())
		Expect(github.CLI.Properties["personal-access-token"].WriteOnly).To(BeTrue())
		Expect(github.Profile.Properties).NotTo(HaveKey("personal-access-token"))
		Expect(github.Context.Properties).NotTo(HaveKey("personal-access-token"))
		Expect(github.Profile.Order).To(HaveLen(len(github.Profile.Properties)))
		Expect(github.Context.Order).To(HaveLen(len(github.Context.Properties)))

		gcp, ok := registry.Provider("gcp")
		Expect(ok).To(BeTrue())
		Expect(gcp.Context.Properties["credentials-file"].CredentialSelector).To(BeTrue())
		Expect(gcp.Context.Properties["credentials-file"].WriteOnly).To(BeFalse())
		Expect(gcp.Context.Properties).To(HaveKey("project-ids"))
		Expect(gcp.Profile.Properties).To(And(
			HaveKey("compliance"), HaveKey("log-level"), HaveKey("output-formats"),
			HaveKey("verbose"), HaveKey("skip-api-check"),
		))
		Expect(gcp.Profile.Properties).NotTo(HaveKey("output-directory"))
		Expect(gcp.CLI.Properties).To(HaveKey("output-directory"))
		Expect(gcp.Profile.Properties["compliance"].Items.Enum).To(ContainElement("cis_5.0_gcp"))
	})

	It("loads deterministic provider projections and OpenAPI components", func() {
		registry, err := schema.LoadFS(schemaFixture())
		Expect(err).NotTo(HaveOccurred())

		Expect(registry.ProviderIDs()).To(Equal([]string{"aws", "gcp"}))
		gcp, ok := registry.Provider("gcp")
		Expect(ok).To(BeTrue())
		Expect(gcp.Profile.Properties).To(HaveKey("compliance"))
		Expect(gcp.Context.Properties).To(HaveKey("project-ids"))
		Expect(gcp.CLI.Properties).To(HaveKey("credentials-file"))
		Expect(gcp.CLIComponentRef).To(Equal("#/components/schemas/ProwlerGCPCLIOptions"))

		components := registry.OpenAPIComponents()
		Expect(components).To(HaveLen(8))
		Expect(components).To(HaveKey("ProwlerGCPProfileOptions"))
		Expect(components).To(HaveKey("ProwlerGCPContextOptions"))

		options := registry.OptionCatalog()
		Expect(options.Discriminator).To(Equal("provider"))
		Expect(options.Variants).To(HaveLen(2))
		Expect(options.Validate()).To(Succeed())
	})

	It("rejects a stale provider artifact", func() {
		fixture := schemaFixture()
		fixture["providers/gcp.generated.json"].Data = append(fixture["providers/gcp.generated.json"].Data, ' ')

		_, err := schema.LoadFS(fixture)
		Expect(err).To(MatchError(ContainSubstring("digest")))
	})

	It("rejects secrets from persistable projections", func() {
		fixture := schemaFixture()
		provider := providerFixture("gcp", "GCP", map[string]schema.JSONSchema{
			"credentials-file": {Type: "string", WriteOnly: true, Owner: "credential"},
		}, map[string]schema.JSONSchema{
			"credentials-file": {Type: "string", WriteOnly: true, Owner: "credential"},
		})
		fixture["providers/gcp.generated.json"].Data = provider
		fixture["manifest.generated.json"].Data = manifestFixture(map[string][]byte{
			"aws": fixture["providers/aws.generated.json"].Data,
			"gcp": provider,
		})

		_, err := schema.LoadFS(fixture)
		Expect(err).To(MatchError(ContainSubstring("credential property credentials-file in profile schema")))
	})

	It("rejects generated credential policy drift", func() {
		fixture := schemaFixture()
		var cloudflare schema.ProviderSchema
		Expect(json.Unmarshal(providerFixture("cloudflare", "Cloudflare", nil, nil), &cloudflare)).To(Succeed())
		cloudflare.Credential = schema.ObjectSchema("Cloudflare credentials", map[string]schema.JSONSchema{
			"connections": {Type: "object"},
		})
		provider, err := json.Marshal(cloudflare)
		Expect(err).NotTo(HaveOccurred())
		fixture["providers/cloudflare.generated.json"] = &fstest.MapFile{Data: provider}
		fixture["manifest.generated.json"].Data = manifestFixture(map[string][]byte{
			"aws":        fixture["providers/aws.generated.json"].Data,
			"cloudflare": provider,
			"gcp":        fixture["providers/gcp.generated.json"].Data,
		})

		_, err = schema.LoadFS(fixture)
		Expect(err).To(MatchError(ContainSubstring("credential schema must expose exactly one envVar")))
	})
})

func schemaFixture() fstest.MapFS {
	providers := map[string][]byte{
		"aws": providerFixture("aws", "AWS", map[string]schema.JSONSchema{
			"compliance": {Type: "array", Items: &schema.JSONSchema{Type: "string"}},
		}, map[string]schema.JSONSchema{
			"profile": {Type: "string", Owner: "context"},
		}),
		"gcp": providerFixture("gcp", "GCP", map[string]schema.JSONSchema{
			"compliance": {Type: "array", Items: &schema.JSONSchema{Type: "string"}},
		}, map[string]schema.JSONSchema{
			"project-ids": {Type: "array", Items: &schema.JSONSchema{Type: "string"}, Owner: "context"},
		}),
	}
	return fstest.MapFS{
		"manifest.generated.json":      {Data: manifestFixture(providers)},
		"providers/aws.generated.json": {Data: providers["aws"]},
		"providers/gcp.generated.json": {Data: providers["gcp"]},
	}
}

func providerFixture(provider, title string, profile, context map[string]schema.JSONSchema) []byte {
	if profile == nil {
		profile = map[string]schema.JSONSchema{}
	}
	if context == nil {
		context = map[string]schema.JSONSchema{}
	}
	profile["provider"] = schema.JSONSchema{Type: "string", Const: provider, ReadOnly: true}
	cli := map[string]schema.JSONSchema{}
	for key, property := range profile {
		cli[key] = property
	}
	for key, property := range context {
		cli[key] = property
	}
	cli["credentials-file"] = schema.JSONSchema{Type: "string", WriteOnly: true, Owner: "credential"}
	document := schema.ProviderSchema{
		Provider:     provider,
		Title:        title,
		Version:      schema.ProwlerVersion,
		SourceCommit: schema.PinnedCommit,
		CLI:          schema.ObjectSchema(title+" CLI options", cli),
		Profile: func() schema.JSONSchema {
			projected := schema.ObjectSchema(title+" profile options", profile)
			projected.Required = []string{"provider"}
			return projected
		}(),
		Context:    schema.ObjectSchema(title+" context options", context),
		Credential: schema.ObjectSchema(title+" credentials", map[string]schema.JSONSchema{}),
	}
	data, err := json.Marshal(document)
	Expect(err).NotTo(HaveOccurred())
	return data
}

func providerIndex(providers []string, provider string) int {
	for index, candidate := range providers {
		if candidate == provider {
			return index
		}
	}
	return -1
}

func manifestFixture(providers map[string][]byte) []byte {
	providerIDs := make([]string, 0, len(providers))
	for provider := range providers {
		providerIDs = append(providerIDs, provider)
	}
	sort.Strings(providerIDs)
	manifest := schema.Manifest{
		Version:       schema.ProwlerVersion,
		SourceCommit:  schema.PinnedCommit,
		ProviderCount: len(providers),
		Providers:     providerIDs,
		Digests:       map[string]string{},
	}
	for provider, data := range providers {
		digest := sha256.Sum256(data)
		manifest.Digests[provider] = hex.EncodeToString(digest[:])
	}
	data, err := json.Marshal(manifest)
	Expect(err).NotTo(HaveOccurred())
	return data
}

func cloudflareCredential(value map[string]any) map[string]any {
	credential := map[string]any{"name": "CLOUDFLARE_API_TOKEN"}
	for key, field := range value {
		credential[key] = field
	}
	return map[string]any{"envVars": []any{credential}}
}
