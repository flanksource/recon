package mute

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/ocsf"
)

var _ = Describe("a mute expression", func() {
	finding := api.Finding{
		DetectionFinding: ocsf.DetectionFinding{
			SeverityID:  ocsf.SeverityIDHigh,
			FindingInfo: &ocsf.FindingInfo{UID: "gcp/bucket_public", Title: "Public bucket"},
			Cloud:       &ocsf.Cloud{Provider: "gcp"},
			Unmapped:    map[string]any{"compliance": []any{"CIS-2.1"}},
		},
		CheckID:   "gcp/bucket_public",
		Host:      "example-project",
		MatchedAt: "//storage.googleapis.com/logs-example",
		Tags:      []string{"storage", "public"},
		Resources: []api.ResourceRef{{UID: "logs-example", Type: "bucket"}},
	}

	// The vocabulary is OCSF's, at the top level, because api.Finding embeds the
	// Detection Finding rather than nesting it.
	It("reads the finding through the published schema", func() {
		Expect(evaluate(`finding.severity_id == 4`, finding)).To(BeTrue())
		Expect(evaluate(`finding.finding_info.title == "Public bucket"`, finding)).To(BeTrue())
		Expect(evaluate(`finding.cloud.provider == "gcp"`, finding)).To(BeTrue())
		Expect(evaluate(`finding.host == "nothing"`, finding)).To(BeFalse())
	})

	// Recon's own identity, which OCSF has no column for, keeps its own names.
	It("reads the identity recon tracks a finding by", func() {
		Expect(evaluate(`finding.checkId == "gcp/bucket_public"`, finding)).To(BeTrue())
	})

	// What used to be finding.raw.resources[0].uid. The subjects are OCSF's own
	// resources array now, so the rule reads one field shallower and against a
	// published name.
	It("reaches the subjects the evidence names", func() {
		Expect(evaluate(`finding.resources[0].uid.startsWith("logs-")`, finding)).To(BeTrue())
		Expect(evaluate(`finding.resources[0].type == "bucket"`, finding)).To(BeTrue())
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
			Expect(Compile(`finding.severity_id == 4`)).To(Succeed())
		})

		It("refuses a syntax error and says where", func() {
			err := Compile(`finding.severity_id == `)
			Expect(err).To(MatchError(ContainSubstring("invalid expression")))
		})

		It("refuses an unknown variable", func() {
			Expect(Compile(`target.class == "prod"`)).To(HaveOccurred())
		})

		// The silent-failure mode this exists to remove. Compiled against a zero
		// Finding, every one of these stored successfully and then muted nothing
		// — which looks exactly like a rule that correctly matched nothing.
		It("refuses a path the schema does not define", func() {
			Expect(Compile(`finding.raw.resources[0].uid == "x"`)).To(HaveOccurred())
			Expect(Compile(`finding.templateId == "x"`)).To(HaveOccurred())
			Expect(Compile(`finding.finding_info.ttle == "x"`)).To(HaveOccurred())
		})

		// Every attribute the generated schema carries is reachable, including
		// the ones no engine recon runs populates today.
		It("accepts a defined path a finding happens not to carry", func() {
			Expect(Compile(`finding.vulnerabilities[0].cve.uid == "CVE-2026-1"`)).To(Succeed())
			Expect(Compile(`finding.evidences[0].http_response.code == 200`)).To(Succeed())
		})
	})

	// unmapped is OCSF's escape hatch for whatever an engine reported that the
	// schema has no name for. It has no fixed keys, so it stays dynamic: reading
	// into it compiles, and answers null on a finding that does not carry it.
	// That is what keeps a rule written for one engine from muting another's.
	It("leaves the engine's own extras dynamic", func() {
		Expect(Compile(`finding.unmapped.absent.deeper == 1`)).To(Succeed())
		Expect(evaluate(`finding.unmapped.absent.deeper == 1`, finding)).To(BeFalse())
		Expect(evaluate(`"CIS-2.1" in finding.unmapped.compliance`, finding)).To(BeTrue())
	})

	It("does not match when the finding lacks the subject the rule reads", func() {
		Expect(evaluate(`finding.resources[9].uid == "x"`, finding)).To(BeFalse())
	})

	// A rule that mutes nothing and a rule that could not be evaluated are
	// different answers, so an expression that does not produce a boolean is an
	// error rather than a silent false.
	It("reports an expression that does not answer yes or no", func() {
		_, err := evaluate(`finding.host`, finding)
		Expect(err).To(MatchError(ContainSubstring("bool")))
	})
})
