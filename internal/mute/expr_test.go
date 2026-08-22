package mute

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("a mute expression", func() {
	finding := api.Finding{
		TemplateID: "gcp/bucket_public",
		Name:       "Public bucket",
		Severity:   api.SeverityHigh,
		Host:       "example-project",
		MatchedAt:  "//storage.googleapis.com/logs-example",
		Tags:       []string{"storage", "public"},
		Raw: map[string]any{
			"resources": []any{map[string]any{"uid": "logs-example", "type": "bucket"}},
		},
	}

	It("reads the finding through its wire names", func() {
		Expect(evaluate(`finding.severity == "high"`, finding)).To(BeTrue())
		Expect(evaluate(`finding.templateId == "gcp/bucket_public"`, finding)).To(BeTrue())
		Expect(evaluate(`finding.host == "nothing"`, finding)).To(BeFalse())
	})

	It("reaches into the engine's own record", func() {
		Expect(evaluate(`finding.raw.resources[0].uid.startsWith("logs-")`, finding)).To(BeTrue())
		Expect(evaluate(`finding.raw.resources[0].type == "bucket"`, finding)).To(BeTrue())
	})

	It("reads list fields", func() {
		Expect(evaluate(`"public" in finding.tags`, finding)).To(BeTrue())
		Expect(evaluate(`"private" in finding.tags`, finding)).To(BeFalse())
	})

	Describe("compiling before storing", func() {
		It("accepts an empty expression, which means the rule has none", func() {
			Expect(Compile("")).To(Succeed())
		})

		It("accepts a usable expression", func() {
			Expect(Compile(`finding.severity == "high"`)).To(Succeed())
		})

		It("refuses a syntax error and says where", func() {
			err := Compile(`finding.severity == `)
			Expect(err).To(MatchError(ContainSubstring("invalid expression")))
		})

		It("refuses an unknown variable", func() {
			Expect(Compile(`target.class == "prod"`)).To(HaveOccurred())
		})
	})

	// gomplate installs cel's nilsafe library with zero values, so reaching
	// through a key an engine did not populate yields null rather than an error.
	// A rule written against one engine's raw record therefore does not mute
	// another engine's findings, which is the behaviour we want and is why
	// evaluation errors are rare rather than routine.
	It("does not match when the finding lacks the field the rule reads", func() {
		Expect(Compile(`finding.raw.absent.deeper == 1`)).To(Succeed())
		Expect(evaluate(`finding.raw.absent.deeper == 1`, finding)).To(BeFalse())
		Expect(evaluate(`finding.raw.resources[9].uid == "x"`, finding)).To(BeFalse())
	})

	// A rule that mutes nothing and a rule that could not be evaluated are
	// different answers, so an expression that does not produce a boolean is an
	// error rather than a silent false.
	It("reports an expression that does not answer yes or no", func() {
		_, err := evaluate(`finding.host`, finding)
		Expect(err).To(MatchError(ContainSubstring("bool")))
	})
})
