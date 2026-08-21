package main

import (
	"testing/fstest"

	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"
)

var _ = Describe("projecting argparse metadata", func() {
	It("separates profile, context, credentials, and runner arguments", func() {
		common := []arguments.Argument{
			profileArgument("compliance", "compliance", arguments.NArgsOneOrMore),
			profileArgument("output-formats", "output_formats", arguments.NArgsOneOrMore),
			runnerArgument("output-directory", "output_directory"),
		}
		common[1].Choices = []string{"csv", "json-asff", "json-ocsf", "html", "sarif"}
		provider := arguments.Provider{Name: "gcp", Arguments: []arguments.Argument{
			contextArgument("project-ids", "project_id", arguments.NArgsOneOrMore),
			credentialArgument("credentials-file", "credentials_file"),
			profileArgument("skip-api-check", "skip_api_check", arguments.NArgsNone),
		}}

		document, err := projectProvider(providerProjectionOptions{Provider: provider, Common: common, Checks: testCatalog()})
		Expect(err).NotTo(HaveOccurred())
		Expect(document.Profile.Properties).To(HaveKey("provider"))
		Expect(document.Profile.Required).To(ContainElement("provider"))
		Expect(document.Profile.Properties).To(HaveKey("compliance"))
		Expect(document.Profile.Properties["compliance"].Items.Enum).To(Equal([]any{"cis_5.0_gcp"}))
		Expect(document.Profile.Properties).To(HaveKey("skip-api-check"))
		Expect(document.Profile.Order).To(Equal([]string{"provider", "skip-api-check", "compliance", "output-formats"}))
		Expect(document.Profile.Properties).NotTo(HaveKey("project-ids"))
		Expect(document.Profile.Properties).NotTo(HaveKey("credentials-file"))
		Expect(document.Profile.Properties).NotTo(HaveKey("output-directory"))
		Expect(document.Context.Properties).To(HaveKey("project-ids"))

		credential := document.CLI.Properties["credentials-file"]
		Expect(credential.WriteOnly).To(BeTrue())
		Expect(credential.Format).To(Equal("password"))
		Expect(credential.SecretReference).To(BeTrue())
		Expect(document.CLI.Properties).To(HaveKey("output-directory"))
		Expect(document.CLI.Properties["output-formats"].Items.Enum).To(Equal([]any{"csv", "json-ocsf", "html"}))
	})

	It("retains argparse aliases, shapes, defaults, and declaration order", func() {
		arg := profileArgument("excluded-checks", "excluded_check", arguments.NArgsOneOrMore)
		arg.Flags = []string{"--excluded-check", "--excluded-checks", "-e"}
		arg.Canonical = "--excluded-checks"
		arg.Default = []string{"gcp_iam_example"}
		arg.Help = "Checks to exclude"

		property, err := projectArgument(argumentProjectionOptions{
			Argument: arg, Choices: []string{"gcp_iam_example"}, Order: 4, IncludeDefault: true,
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(property).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"Type":         Equal("array"),
			"Description":  Equal("Checks to exclude"),
			"Flags":        Equal([]string{"--excluded-check", "--excluded-checks", "-e"}),
			"Destination":  Equal("excluded_check"),
			"ProwlerOrder": gstruct.PointTo(Equal(4)),
		}))
		Expect(property.MinItems).To(gstruct.PointTo(Equal(1)))
		Expect(property.Items.Enum).To(Equal([]any{"gcp_iam_example"}))
		Expect(property.Default).To(Equal([]string{"gcp_iam_example"}))
	})

	It("projects provider credentials from the security policy instead of argparse", func() {
		cloudflare, err := projectProvider(providerProjectionOptions{
			Provider: arguments.Provider{Name: "cloudflare"}, Checks: testCatalog(),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(cloudflare.Credential.Properties).To(HaveKey("envVars"))
		Expect(cloudflare.Credential.Properties).NotTo(HaveKey("connections"))

		envVars := cloudflare.Credential.Properties["envVars"]
		Expect(envVars.MinItems).To(gstruct.PointTo(Equal(1)))
		Expect(envVars.MaxItems).To(gstruct.PointTo(Equal(1)))
		Expect(envVars.Items.Properties["name"].Const).To(Equal("CLOUDFLARE_API_TOKEN"))
		Expect(envVars.Items.Properties["value"].WriteOnly).To(BeTrue())
		Expect(envVars.Items.Properties["configured"].ReadOnly).To(BeTrue())

		valueFrom := envVars.Items.Properties["valueFrom"]
		Expect(valueFrom.Properties).To(SatisfyAll(
			HaveLen(4), HaveKey("secretKeyRef"), HaveKey("configMapKeyRef"),
			HaveKey("helmRef"), HaveKey("onePassword"),
		))
		Expect(valueFrom.Properties).NotTo(HaveKey("serviceAccount"))

		gcp, err := projectProvider(providerProjectionOptions{
			Provider: arguments.Provider{Name: "gcp"}, Checks: testCatalog(),
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(gcp.Credential.Properties).To(BeEmpty())
	})

	It("detects missing, stale, and extra checked-in artifacts", func() {
		expected := map[string][]byte{
			schemaArtifactRoot + "/manifest.generated.json":      []byte("manifest"),
			schemaArtifactRoot + "/providers/gcp.generated.json": []byte("gcp"),
		}
		Expect(checkArtifacts(fstest.MapFS{
			schemaArtifactRoot + "/manifest.generated.json":      {Data: []byte("manifest")},
			schemaArtifactRoot + "/providers/gcp.generated.json": {Data: []byte("old")},
			schemaArtifactRoot + "/providers/old.generated.json": {Data: []byte("old")},
		}, expected)).To(MatchError(And(
			ContainSubstring("stale "+schemaArtifactRoot+"/providers/gcp.generated.json"),
			ContainSubstring("unexpected "+schemaArtifactRoot+"/providers/old.generated.json"),
		)))
	})
})

func testCatalog() *catalog.Catalog {
	return &catalog.Catalog{
		Providers: []catalog.Provider{{ID: "cloudflare", Static: true}, {ID: "gcp", Static: true}},
		Profiles:  []catalog.Profile{{Provider: "gcp", ComplianceID: "cis_5.0_gcp"}},
		Checks:    []catalog.Check{{Provider: "gcp", ID: "gcp_iam_example", Service: "iam", Categories: []string{"identity"}, ResourceGroup: "identity"}},
	}
}

func profileArgument(key, destination string, nargs arguments.NArgs) arguments.Argument {
	valueType := arguments.TypeString
	action := arguments.ActionStore
	if nargs == arguments.NArgsNone {
		valueType = arguments.TypeBoolean
		action = arguments.ActionStoreTrue
	}
	return arguments.Argument{
		Key: key, Destination: destination, Flags: []string{"--" + key}, Canonical: "--" + key,
		Group: "Selection", Action: action, NArgs: nargs, Type: valueType,
		Policy: arguments.Policy{Owner: arguments.OwnerProfile},
	}
}

func contextArgument(key, destination string, nargs arguments.NArgs) arguments.Argument {
	arg := profileArgument(key, destination, nargs)
	arg.Policy.Owner = arguments.OwnerContext
	return arg
}

func credentialArgument(key, destination string) arguments.Argument {
	arg := profileArgument(key, destination, arguments.NArgsOptional)
	arg.Policy = arguments.Policy{Owner: arguments.OwnerCredential, Sensitive: true, Redact: true}
	return arg
}

func runnerArgument(key, destination string) arguments.Argument {
	arg := profileArgument(key, destination, arguments.NArgsOptional)
	arg.Policy.Owner = arguments.OwnerRunner
	return arg
}
