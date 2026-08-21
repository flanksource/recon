package arguments_test

import (
	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("deterministic Prowler argv", func() {
	var catalogue arguments.Catalogue

	BeforeEach(func() {
		catalogue = testCatalogue()
		Expect(catalogue.ApplyPolicies()).To(Succeed())
		Expect(catalogue.Validate()).To(Succeed())
	})

	It("emits provider arguments before common arguments in parser order", func() {
		argv, err := catalogue.BuildArgv("gcp", arguments.Inputs{
			Context: map[string]any{"project-ids": []string{"workload-prod-eu-02", "flanksource-prod"}},
			Profile: map[string]any{
				"skip-api-check": true, "output-formats": []any{"csv", "json-ocsf", "html"},
				"verbose": true, "log-level": "DEBUG", "excluded-checks": []string{"gcp_one", "gcp_two"},
				"compliance": []string{"cis_5.0_gcp"},
			},
			Runner: map[string]any{"output-directory": "output"},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(argv).To(Equal([]string{
			"gcp", "--project-ids", "workload-prod-eu-02", "flanksource-prod", "--skip-api-check",
			"--output-formats", "csv", "json-ocsf", "html", "--output-directory", "output",
			"--verbose", "--log-level", "DEBUG", "--excluded-checks", "gcp_one", "gcp_two",
			"--compliance", "cis_5.0_gcp",
		}))
	})

	It("repeats append actions in input order", func() {
		images := arguments.Catalogue{Providers: []arguments.Provider{{Name: "image", Arguments: []arguments.Argument{
			argument("image", "images", "--image", 0, arguments.ActionAppend, arguments.NArgsOne, arguments.TypeString),
		}}}}
		Expect(images.ApplyPolicies()).To(Succeed())

		argv, err := images.BuildArgv("image", arguments.Inputs{Context: map[string]any{
			"image": []string{"acme/app:1", "acme/app:2"},
		}})
		Expect(err).ToNot(HaveOccurred())
		Expect(argv).To(Equal([]string{"image", "--image", "acme/app:1", "--image", "acme/app:2"}))
	})

	It("omits false booleans and absent defaults", func() {
		argv, err := catalogue.BuildArgv("gcp", arguments.Inputs{
			Profile: map[string]any{"verbose": false, "skip-api-check": false},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(argv).To(Equal([]string{"gcp"}))
	})

	It("normalizes runnable provider aliases to catalogue identities", func() {
		ociCatalogue := arguments.Catalogue{Providers: []arguments.Provider{{Name: "oraclecloud", Arguments: []arguments.Argument{
			argument("compartment-id", "compartment_id", "--compartment-id", 0, arguments.ActionStore, arguments.NArgsOptional, arguments.TypeString),
		}}}}
		Expect(ociCatalogue.ApplyPolicies()).To(Succeed())

		argv, err := ociCatalogue.BuildArgv("oci", arguments.Inputs{Context: map[string]any{"compartment-id": "tenant-x"}})
		Expect(err).ToNot(HaveOccurred())
		Expect(argv).To(Equal([]string{"oraclecloud", "--compartment-id", "tenant-x"}))
	})

	It("enforces ownership, forbidden arguments, and unknown keys", func() {
		_, err := catalogue.BuildArgv("gcp", arguments.Inputs{
			Profile: map[string]any{"project-ids": []string{"tenant-x"}},
		})
		Expect(err).To(MatchError(ContainSubstring("belongs to context, not profile")))

		_, err = catalogue.BuildArgv("gcp", arguments.Inputs{
			Runner: map[string]any{"config-file": "prowler.yaml"},
		})
		Expect(err).To(MatchError(ContainSubstring("forbidden")))

		_, err = catalogue.BuildArgv("gcp", arguments.Inputs{
			Profile: map[string]any{"future-option": true},
		})
		Expect(err).To(MatchError(ContainSubstring("unknown argument \"future-option\"")))

		_, err = catalogue.PartitionProviderContext("future-provider", nil, arguments.ProviderContextOptions{
			Mode: arguments.CredentialModeAmbient,
		})
		Expect(err).To(MatchError(ContainSubstring("unsupported Prowler provider")))
	})

	It("requires exactly one active selection from required mutually exclusive groups", func() {
		catalogue.CommonMutualExclusions[0].Required = true

		_, err := catalogue.BuildArgv("gcp", arguments.Inputs{})
		Expect(err).To(MatchError(ContainSubstring("selection requires exactly one")))

		_, err = catalogue.BuildArgv("gcp", arguments.Inputs{Profile: map[string]any{
			"checks": []string{"gcp_one"}, "compliance": []string{"cis_5.0_gcp"},
		}})
		Expect(err).To(MatchError(ContainSubstring("selection accepts only one")))
	})

	It("validates nargs, choices, and scalar types without coercion", func() {
		_, err := catalogue.BuildArgv("gcp", arguments.Inputs{Profile: map[string]any{
			"output-formats": "csv",
		}})
		Expect(err).To(MatchError(ContainSubstring("must be an array")))

		_, err = catalogue.BuildArgv("gcp", arguments.Inputs{Profile: map[string]any{
			"log-level": "TRACE",
		}})
		Expect(err).To(MatchError(ContainSubstring("must be one of")))
	})

	It("partitions configured credentials from provider context and rejects them in ambient mode", func() {
		inputs, err := catalogue.PartitionProviderContext("gcp", map[string]any{
			"project-ids": []string{"tenant-x"}, "credentials-file": "/secret/key.json",
		}, arguments.ProviderContextOptions{Mode: arguments.CredentialModeConfigured})
		Expect(err).ToNot(HaveOccurred())
		Expect(inputs.Context).To(Equal(map[string]any{
			"project-ids": []string{"tenant-x"}, "credentials-file": "/secret/key.json",
		}))
		Expect(inputs.Credential).To(BeEmpty())

		_, err = catalogue.PartitionProviderContext("gcp", map[string]any{
			"credentials-file": "/secret/key.json",
		}, arguments.ProviderContextOptions{Mode: arguments.CredentialModeAmbient})
		Expect(err).To(MatchError(ContainSubstring("credential selector")))

		_, err = catalogue.PartitionProviderContext("gcp", map[string]any{
			"project-ids": []string{"tenant-x"},
		}, arguments.ProviderContextOptions{Mode: arguments.CredentialModeConfigured})
		Expect(err).To(MatchError(ContainSubstring("requires an explicit credential selector")))

		_, err = catalogue.PartitionProviderContext("gcp", map[string]any{
			"project-ids": []string{"tenant-x"},
		}, arguments.ProviderContextOptions{Mode: arguments.CredentialModeConfigured, RuntimeCredentials: true})
		Expect(err).ToNot(HaveOccurred())

		_, err = catalogue.PartitionProviderContext("gcp", map[string]any{
			"project-ids": []string{"tenant-x"},
		}, arguments.ProviderContextOptions{Mode: arguments.CredentialModeAmbient, RuntimeCredentials: true})
		Expect(err).To(MatchError(ContainSubstring("runtime credentials are not allowed in ambient credential mode")))
	})

	It("keeps direct secrets out of persisted provider context", func() {
		github := arguments.Catalogue{Providers: []arguments.Provider{{Name: "github", Arguments: []arguments.Argument{
			argument("personal-access-token", "personal_access_token", "--personal-access-token", 0, arguments.ActionStore, arguments.NArgsOptional, arguments.TypeString),
			argument("github-app-id", "github_app_id", "--github-app-id", 1, arguments.ActionStore, arguments.NArgsOptional, arguments.TypeString),
		}}}}
		Expect(github.ApplyPolicies()).To(Succeed())

		_, err := github.PartitionProviderContext("github", map[string]any{
			"personal-access-token": "top-secret-token", "github-app-id": "app-id",
		}, arguments.ProviderContextOptions{Mode: arguments.CredentialModeConfigured})
		Expect(err).To(MatchError(And(
			ContainSubstring("runtime-only credential argument"),
			Not(ContainSubstring("top-secret-token")),
		)))
	})
})

func testCatalogue() arguments.Catalogue {
	common := []arguments.Argument{
		argument("output-formats", "output_formats", "--output-formats", 0, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
		argument("output-directory", "output_directory", "--output-directory", 1, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
		argument("verbose", "verbose", "--verbose", 2, arguments.ActionStoreTrue, arguments.NArgsNone, arguments.TypeBoolean),
		argument("log-level", "log_level", "--log-level", 3, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
		argument("excluded-checks", "excluded_check", "--excluded-checks", 4, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
		argument("checks", "check", "--checks", 5, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
		argument("compliance", "compliance", "--compliance", 6, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
		argument("config-file", "config_file", "--config-file", 7, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
	}
	common[0].Choices = []string{"csv", "json", "json-ocsf", "html"}
	common[2].Default = false
	common[3].Choices = []string{"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

	return arguments.Catalogue{
		Common: common,
		CommonMutualExclusions: []arguments.MutualExclusion{{
			Name: "selection", Keys: []string{"checks", "compliance"},
		}},
		Providers: []arguments.Provider{{Name: "gcp", Arguments: []arguments.Argument{
			argument("project-ids", "project_id", "--project-ids", 0, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
			argument("skip-api-check", "skip_api_check", "--skip-api-check", 1, arguments.ActionStoreTrue, arguments.NArgsNone, arguments.TypeBoolean),
			argument("credentials-file", "credentials_file", "--credentials-file", 2, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
		}}},
	}
}
