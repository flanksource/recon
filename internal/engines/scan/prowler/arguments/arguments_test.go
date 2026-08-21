package arguments_test

import (
	"encoding/json"

	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Prowler argument metadata", func() {
	It("covers the pinned built-in provider set in deterministic order", func() {
		Expect(arguments.BuiltInProviders).To(Equal([]string{
			"alibabacloud", "aws", "azure", "cloudflare", "e2enetworks", "gcp", "github",
			"googleworkspace", "huaweicloud", "iac", "image", "kubernetes", "linode", "llm",
			"m365", "mongodbatlas", "nhn", "okta", "openstack", "oraclecloud", "scaleway",
			"stackit", "vercel",
		}))
		m365, err := arguments.NormalizeProvider("microsoft365")
		Expect(err).ToNot(HaveOccurred())
		Expect(m365).To(Equal("m365"))
		oci, err := arguments.NormalizeProvider("oci")
		Expect(err).ToNot(HaveOccurred())
		Expect(oci).To(Equal("oraclecloud"))
		Expect(arguments.IsBuiltInProvider("oci")).To(BeTrue())
	})

	It("overlays policy by argparse destination and rejects unknown arguments", func() {
		catalogue := arguments.Catalogue{Providers: []arguments.Provider{{
			Name: "gcp",
			Arguments: []arguments.Argument{
				argument("project-ids", "project_id", "--project-ids", 0, arguments.ActionStore, arguments.NArgsOneOrMore, arguments.TypeString),
				argument("credentials-file", "credentials_file", "--credentials-file", 1, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
			},
		}}}

		Expect(catalogue.ApplyPolicies()).To(Succeed())
		Expect(catalogue.Providers[0].Arguments[0].Policy.Owner).To(Equal(arguments.OwnerContext))
		Expect(catalogue.Providers[0].Arguments[1].Policy).To(Equal(arguments.Policy{
			Owner: arguments.OwnerContext, Redact: true, CredentialSelector: true,
		}))

		catalogue.Providers[0].Arguments = append(catalogue.Providers[0].Arguments,
			argument("future-option", "future_option", "--future-option", 2, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString))
		Expect(catalogue.ApplyPolicies()).To(MatchError(ContainSubstring("unknown gcp argument destination \"future_option\"")))
	})

	It("loads only a complete, validated built-in catalogue", func() {
		data, err := json.Marshal(arguments.Catalogue{})
		Expect(err).ToNot(HaveOccurred())

		_, err = arguments.LoadJSON(data)
		Expect(err).To(MatchError(ContainSubstring("missing built-in providers")))
	})

	It("rejects bridge fields outside the normalized contract", func() {
		_, err := arguments.LoadJSON([]byte(`{"common":[],"providers":[],"sensitiveFlags":{},"future":true}`))
		Expect(err).To(MatchError(ContainSubstring("unknown field \"future\"")))
	})

	It("rejects unsupported argparse constructs and malformed aliases", func() {
		catalogue := arguments.Catalogue{Providers: []arguments.Provider{{
			Name: "gcp",
			Arguments: []arguments.Argument{
				argument("project-ids", "project_id", "--project-ids", 0, "extend", arguments.NArgsOneOrMore, arguments.TypeString),
			},
		}}}
		catalogue.Providers[0].Arguments[0].Policy = arguments.Policy{Owner: arguments.OwnerContext}

		Expect(catalogue.Validate()).To(MatchError(ContainSubstring("unsupported action \"extend\"")))

		catalogue.Providers[0].Arguments[0].Action = arguments.ActionStore
		catalogue.Providers[0].Arguments[0].Canonical = "--missing-alias"
		Expect(catalogue.Validate()).To(MatchError(ContainSubstring("canonical flag")))
	})

	It("requires compatibility aliases to be merged by destination", func() {
		catalogue := arguments.Catalogue{Providers: []arguments.Provider{{Name: "m365", Arguments: []arguments.Argument{
			argument("sp-env-auth", "sp_env_auth", "--sp-env-auth", 0, arguments.ActionStoreTrue, arguments.NArgsNone, arguments.TypeBoolean),
			argument("env-auth", "sp_env_auth", "--env-auth", 1, arguments.ActionStoreTrue, arguments.NArgsNone, arguments.TypeBoolean),
		}}}}
		Expect(catalogue.ApplyPolicies()).To(Succeed())

		Expect(catalogue.Validate()).To(MatchError(ContainSubstring("duplicate destination \"sp_env_auth\"")))
	})

	It("fails when upstream sensitivity and the security overlay drift", func() {
		catalogue := arguments.Catalogue{
			Common: []arguments.Argument{
				argument("shodan-api-key", "shodan", "--shodan", 0, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
			},
			SensitiveFlags: map[string][]string{"common": {"--shodan"}},
		}
		Expect(catalogue.ApplyPolicies()).To(Succeed())
		Expect(catalogue.ValidateSensitivity()).To(Succeed())

		catalogue.Common[0].Policy.Sensitive = false
		Expect(catalogue.ValidateSensitivity()).To(MatchError(ContainSubstring("is not classified sensitive")))
	})

	It("allows the security overlay to classify additional direct secrets", func() {
		catalogue := arguments.Catalogue{
			Providers: []arguments.Provider{{Name: "aws", Arguments: []arguments.Argument{
				argument("external-id", "external_id", "--external-id", 0, arguments.ActionStore, arguments.NArgsOptional, arguments.TypeString),
			}}},
			SensitiveFlags: map[string][]string{"common": {}, "aws": {}},
		}
		Expect(catalogue.ApplyPolicies()).To(Succeed())
		Expect(catalogue.Providers[0].Arguments[0].Policy.Sensitive).To(BeTrue())
		Expect(catalogue.ValidateSensitivity()).To(Succeed())
	})
})

func argument(key, destination, canonical string, order int, action arguments.Action, nargs arguments.NArgs, valueType arguments.ValueType) arguments.Argument {
	return arguments.Argument{
		Key: key, Destination: destination, Flags: []string{canonical}, Canonical: canonical,
		Order: order, Action: action, NArgs: nargs, Type: valueType,
	}
}
