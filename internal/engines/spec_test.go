package engines_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/deps/pkg/types"

	"github.com/flanksource/recon/internal/engines"
)

// spawned is a minimally valid spec for an engine with a binary — the shape
// every assertion below varies one field of.
func spawned() engines.Spec {
	return engines.Spec{
		Name:   "example",
		Binary: "example",
		Install: types.Package{
			Name: "example", Manager: "github_release", VersionCommand: "--version",
		},
		Options:  engines.OptionsFromSections(nil),
		Defaults: engines.DefaultProfile{Name: "default"},
	}
}

var _ = Describe("an engine spec", func() {
	Describe("Subject", func() {
		It("defaults to the endpoint list", func() {
			// The zero value has to be what a network scanner wants, or every
			// existing engine would need a field it has no opinion about.
			Expect(spawned().Subject).To(Equal(engines.SubjectEndpoints))
			Expect(spawned().Validate()).To(Succeed())
		})

		It("accepts an engine whose subject is cloud accounts", func() {
			spec := spawned()
			spec.Subject = engines.SubjectAccounts

			Expect(spec.Validate()).To(Succeed())
		})

		It("rejects a subject the runtime cannot resolve", func() {
			// The runtime switches on this to decide what the selector resolves
			// to. An unrecognised value would fall through to the endpoint
			// branch and scan addresses for an engine that wanted accounts.
			spec := spawned()
			spec.Subject = "clusters"

			Expect(spec.Validate()).To(MatchError(ContainSubstring("unknown subject")))
		})
	})

	Describe("the binary contract", func() {
		It("holds for a spawned engine", func() {
			spec := spawned()
			spec.Install.VersionCommand = ""

			// Without a version command `doctor` cannot tell an outdated binary
			// from a current one, and a run cannot record what it used.
			Expect(spec.Validate()).To(MatchError(ContainSubstring("version_command is required")))
		})

		It("does not apply to a linked-in engine", func() {
			// There is nothing to provision, so the fields describing how to
			// provision it describe nothing.
			Expect(engines.Spec{
				Name:      "linked",
				InProcess: true,
				Options:   engines.OptionsFromSections(nil),
				Defaults:  engines.DefaultProfile{Name: "default"},
			}.Validate()).To(Succeed())
		})

		It("accepts an explicitly external PATH prerequisite without a deps package", func() {
			spec := spawned()
			spec.Provisioning = engines.ProvisioningPathOnly
			spec.Version = "5.40.0"
			spec.Install = types.Package{
				VersionCommand: "--version",
				VersionRegex:   `prowler\s+(\d+\.\d+\.\d+)`,
			}
			spec.InstallInstructions = "pipx install prowler==5.40.0"

			Expect(spec.Validate()).To(Succeed())
		})

		It("requires external install instructions for a PATH-only prerequisite", func() {
			spec := spawned()
			spec.Provisioning = engines.ProvisioningPathOnly
			spec.Version = "5.40.0"
			spec.Install = types.Package{VersionCommand: "--version"}

			Expect(spec.Validate()).To(MatchError(ContainSubstring("install instructions are required")))
		})
	})

	Describe("provider option catalogs", func() {
		providerSchema := func(provider string, properties engines.JSONSchema) engines.JSONSchema {
			properties["provider"] = engines.JSONSchema{
				"type": "string", "const": provider, "readOnly": true,
			}
			return engines.JSONSchema{
				"$schema":              "https://json-schema.org/draft/2020-12/schema",
				"type":                 "object",
				"additionalProperties": false,
				"required":             []any{"provider"},
				"properties":           properties,
			}
		}

		catalog := func() engines.OptionCatalog {
			return engines.OptionCatalog{
				Discriminator: "provider",
				Variants: []engines.OptionVariant{
					{
						ID: "gcp", Title: "Google Cloud",
						Schema: providerSchema("gcp", engines.JSONSchema{
							"project-ids": engines.JSONSchema{
								"type": "array", "items": engines.JSONSchema{"type": "string"},
							},
						}),
						ContextSchema: &engines.JSONSchema{
							"type": "object", "additionalProperties": false,
							"properties": engines.JSONSchema{
								"organization-id": engines.JSONSchema{"type": "string"},
							},
						},
						SchemaRef:             "#/components/schemas/ProwlerGCPProfile",
						ContextSchemaRef:      "#/components/schemas/ProwlerGCPContext",
						CLIArgumentsSchemaRef: "#/components/schemas/ProwlerGCPArguments",
					},
					{
						ID: "github", Title: "GitHub",
						Schema: providerSchema("github", engines.JSONSchema{
							"repository": engines.JSONSchema{"type": "string", "minLength": 1},
						}),
					},
				},
			}
		}

		It("selects and fully validates the schema for the configured provider", func() {
			options := catalog()

			Expect(options.ValidateConfig(map[string]any{
				"provider": "gcp", "project-ids": []any{"workload-prod-eu-02"},
			})).To(Succeed())
			Expect(options.ValidateConfig(map[string]any{
				"provider": "gcp", "repository": "flanksource/recon",
			})).To(MatchError(ContainSubstring("repository")))
			Expect(options.ValidateConfig(map[string]any{
				"provider": "github", "repository": "",
			})).To(MatchError(ContainSubstring("minLength")))

			spec := spawned()
			spec.Options = options
			Expect(spec.ValidateContext(
				map[string]any{"provider": "gcp"},
				map[string]any{"organization-id": "123456789"},
			)).To(Succeed())
			Expect(spec.ValidateContext(
				map[string]any{"provider": "gcp"},
				map[string]any{"repository": "flanksource/recon"},
			)).To(MatchError(ContainSubstring("repository")))
		})

		It("fails loudly when the provider cannot select exactly one variant", func() {
			options := catalog()

			Expect(options.ValidateConfig(map[string]any{})).To(MatchError(ContainSubstring("provider is required")))
			Expect(options.ValidateConfig(map[string]any{"provider": true})).
				To(MatchError(ContainSubstring("provider must be a string")))
			Expect(options.ValidateConfig(map[string]any{"provider": "azure"})).
				To(MatchError(ContainSubstring("unknown provider \"azure\"")))
		})

		It("rejects a catalog whose discriminator does not match its variant", func() {
			options := catalog()
			options.Variants[0].Schema["required"] = []any{}

			Expect(options.Validate()).To(MatchError(ContainSubstring("must require discriminator")))
		})

		It("compiles optional context schemas when validating the catalog", func() {
			options := catalog()
			*options.Variants[0].ContextSchema = engines.JSONSchema{"type": 12}

			Expect(options.Validate()).To(MatchError(ContainSubstring("context schema")))
		})

		It("does not let a run override change the stored provider", func() {
			spec := spawned()
			spec.Options = catalog()

			base := map[string]any{"provider": "gcp", "project-ids": []any{"workload-prod-eu-02"}}
			Expect(spec.ValidateOverrides(base, map[string]any{"provider": "gcp"})).To(Succeed())
			Expect(spec.ValidateOverrides(base, map[string]any{"provider": "github"})).
				To(MatchError(ContainSubstring("cannot override provider")))
		})
	})

	Describe("converting the existing section catalogs", func() {
		It("produces one ordered full-schema variant", func() {
			options := engines.OptionsFromSections(engines.Sections{{
				ID: "network", Title: "Network",
				Properties: []engines.Field{
					engines.Int("rate", "Rate", "Packets per second", 1),
					engines.Bool("verbose", "Verbose", "Show progress"),
				},
			}})

			Expect(options.Validate()).To(Succeed())
			Expect(options.Variants).To(HaveLen(1))
			Expect(options.Variants[0].Schema).To(HaveKeyWithValue("x-order", []string{"rate", "verbose"}))
			Expect(options.Variants[0].Schema).To(HaveKeyWithValue("x-sections", []engines.OptionSection{{
				ID: "network", Title: "Network",
			}}))
			Expect(options.ValidateConfig(map[string]any{"rate": 10, "verbose": true})).To(Succeed())
			Expect(options.ValidateConfig(map[string]any{"unknown": true})).
				To(MatchError(ContainSubstring("unknown")))
		})
	})
})
