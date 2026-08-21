package arguments_test

import (
	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Prowler argument security", func() {
	var catalogue arguments.Catalogue

	BeforeEach(func() {
		catalogue = testCatalogue()
		catalogue.Providers[0].Arguments[2].Flags = []string{"--credentials-file", "-c"}
		Expect(catalogue.ApplyPolicies()).To(Succeed())
		Expect(catalogue.Validate()).To(Succeed())
	})

	It("redacts credential and path values for canonical flags and aliases", func() {
		for _, argv := range [][]string{
			{"gcp", "--credentials-file", "/secret/key.json", "--verbose"},
			{"gcp", "-c=/secret/key.json", "--verbose"},
		} {
			redacted, err := catalogue.RedactArgv("gcp", argv)
			Expect(err).ToNot(HaveOccurred())
			Expect(redacted).To(ContainElement(ContainSubstring(arguments.RedactedValue)))
			Expect(redacted).ToNot(ContainElement(ContainSubstring("/secret/key.json")))
		}
	})

	It("fails closed on unknown flags without returning partially redacted output", func() {
		redacted, err := catalogue.RedactArgv("gcp", []string{
			"gcp", "--credentials-file", "/secret/key.json", "--future-flag", "value",
		})

		Expect(err).To(MatchError(ContainSubstring("unknown flag \"--future-flag\"")))
		Expect(redacted).To(BeNil())
	})

	It("redacts every inline and following value of a variadic credential", func() {
		catalogue.Providers[0].Arguments[2].NArgs = arguments.NArgsOneOrMore

		redacted, err := catalogue.RedactArgv("gcp", []string{
			"gcp", "--credentials-file=/secret/first.json", "/secret/second.json", "--verbose",
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(redacted).ToNot(ContainElement(ContainSubstring("/secret/")))
		Expect(redacted).To(Equal([]string{
			"gcp", "--credentials-file=" + arguments.RedactedValue, arguments.RedactedValue, "--verbose",
		}))
	})

	It("rejects persistence of sensitive values without echoing them", func() {
		github := arguments.Catalogue{Providers: []arguments.Provider{{Name: "github", Arguments: []arguments.Argument{
			argument("personal-access-token", "personal_access_token", "--personal-access-token", 0, arguments.ActionStore, arguments.NArgsOne, arguments.TypeString),
		}}}}
		Expect(github.ApplyPolicies()).To(Succeed())

		err := github.RejectSensitive("github", map[string]any{"personal-access-token": "top-secret-token"})
		Expect(err).To(MatchError(And(
			ContainSubstring("personal-access-token"),
			Not(ContainSubstring("top-secret-token")),
		)))

		Expect(catalogue.RejectSensitive("gcp", map[string]any{
			"credentials-file": "/secret/key.json",
		})).To(Succeed())
		Expect(catalogue.RejectSensitive("future-provider", nil)).To(MatchError(ContainSubstring("unsupported Prowler provider")))
	})
})
