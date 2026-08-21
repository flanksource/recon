package trivy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

func TestTrivy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "trivy")
}

// contextID is the inventory target the fixture stands in for. Every finding
// carries it, so it is named once rather than repeated as a literal.
const contextID = "build-artifacts"

// The fixture is real output: trivy 0.69 scanning a directory holding a
// requirements.txt, a Dockerfile, an AWS credentials file and a LICENSE, with
// every scanner enabled. It is the only report shape recon parses, so parsing
// something trivy actually wrote is the whole point of the fixture.
func fixture() *parsed {
	GinkgoHelper()
	report, err := readReport(filepath.Join("testdata", "filesystem-report.json"), contextID)
	Expect(err).ToNot(HaveOccurred())
	return report
}

func findingNamed(report *parsed, templateID string) api.Finding {
	GinkgoHelper()
	for _, finding := range report.Findings {
		if finding.TemplateID == templateID {
			return finding
		}
	}
	Fail("no finding for " + templateID)
	return api.Finding{}
}

var _ = Describe("reading a trivy report", func() {
	It("reports every finding class the run produced", func() {
		report := fixture()

		matchers := map[string]int{}
		for _, finding := range report.Findings {
			matchers[finding.MatcherName]++
		}
		// Two vulnerabilities in requirements.txt, two failed Dockerfile checks,
		// three secrets in the credentials file, one detected licence.
		Expect(matchers).To(Equal(map[string]int{
			"vulnerability": 2, "misconfiguration": 2, "secret": 3, "license": 1,
		}))
	})

	It("addresses every finding to the target it was resolved from", func() {
		report := fixture()
		for _, finding := range report.Findings {
			Expect(finding.TargetID).To(Equal(contextID))
			Expect(finding.Type).To(Equal(EngineName))
			// The artifact trivy named, not the inventory id: they are different
			// identities and a finding needs both.
			Expect(finding.Host).To(Equal("sample"))
		}
	})

	It("projects a vulnerability onto the package it is in", func() {
		finding := findingNamed(fixture(), "CVE-2019-19844")

		Expect(finding.Name).To(Equal("Django: crafted email address allows account takeover"))
		Expect(finding.Severity).To(Equal(api.SeverityCritical))
		Expect(finding.MatchedAt).To(Equal("requirements.txt: Django@2.0.1"))
		Expect(finding.Remediation).To(Equal("Upgrade Django from 2.0.1 to 1.11.27, 2.2.9, 3.0.1"))
		Expect(finding.Tags).To(ContainElements(
			"class:lang-pkgs", "type:pip", "package:Django", "status:fixed", "cwe:CWE-640"))
		// The primary URL leads, because it is the one page that summarises the
		// rest.
		Expect(finding.Reference[0]).To(Equal("https://avd.aquasec.com/nvd/cve-2019-19844"))
		// The engine's own record survives the projection: the typed fields are
		// what the UI filters on, not the whole of what trivy said.
		Expect(finding.Raw).To(HaveKeyWithValue("PkgIdentifier", HaveKeyWithValue(
			"PURL", "pkg:pypi/django@2.0.1")))
	})

	It("addresses a misconfiguration to the line that caused it", func() {
		finding := findingNamed(fixture(), "DS-0002")

		Expect(finding.Name).To(Equal("Image user should not be 'root'"))
		Expect(finding.Severity).To(Equal(api.SeverityHigh))
		Expect(finding.MatchedAt).To(Equal("Dockerfile:2"))
		Expect(finding.Extracted).To(Equal([]string{"Last USER command in Dockerfile should not be 'root'"}))
		Expect(finding.Remediation).To(Equal("Add 'USER <non root user name>' line to the Dockerfile"))
		Expect(finding.Tags).To(ContainElements("class:config", "type:dockerfile", "provider:Dockerfile"))
	})

	It("addresses a check with no cause line to the file alone", func() {
		// DS-0026 is a missing HEALTHCHECK: the fault is the absence of a line,
		// so there is no line to point at and "Dockerfile:0" would point at one.
		Expect(findingNamed(fixture(), "DS-0026").MatchedAt).To(Equal("Dockerfile"))
	})

	It("records a secret without lifting the matched text out of the record", func() {
		finding := findingNamed(fixture(), "github-pat")

		Expect(finding.Name).To(Equal("GitHub Personal Access Token"))
		Expect(finding.MatchedAt).To(Equal("credentials:4"))
		Expect(finding.Tags).To(ContainElement("category:GitHub"))
		Expect(finding.Remediation).To(Equal("Rotate the credential and remove it from credentials"))
		Expect(finding.Extracted).To(BeEmpty())
		// Trivy masks the value before writing the report and recon keeps it
		// that way; nothing here copies it into a typed field.
		Expect(finding.Raw).To(HaveKeyWithValue("Match", ContainSubstring("****")))
	})

	It("names the file a licence was detected in", func() {
		finding := findingNamed(fixture(), "license/MIT")

		Expect(finding.Name).To(Equal("MIT licence in LICENSE"))
		Expect(finding.Severity).To(Equal(api.SeverityLow))
		Expect(finding.Tags).To(ContainElements("category:notice", "license:MIT"))
		Expect(finding.Reference).To(Equal([]string{"https://spdx.org/licenses/MIT.html"}))
	})

	It("counts everything examined, not only what it reported", func() {
		stats := fixture().Stats()

		// Eight entries considered and eight reported here, but the two are
		// different questions — the passing-check case below is where they part.
		Expect(stats.Total).To(Equal(float64(8)))
		Expect(stats.Matched).To(Equal(float64(8)))
		// One template per distinct rule: two CVEs, two Dockerfile checks, three
		// secret rules, one licence.
		Expect(stats.Templates).To(Equal(float64(8)))
	})
})

var _ = Describe("reading a report that is not all findings", func() {
	parse := func(body string) (*parsed, error) {
		var report document
		Expect(json.Unmarshal([]byte(body), &report)).To(Succeed())
		return report.parse(contextID)
	}

	It("counts a passing check without reporting it", func() {
		// --include-non-failures puts the checks that passed in the report so
		// the retained document shows the whole benchmark. A check that passed
		// is not something to act on, so it is counted and not reported.
		report, err := parse(`{
			"SchemaVersion": 2, "ArtifactName": "sample", "Results": [{
				"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
				"Misconfigurations": [
					{"ID": "DS-0001", "Title": "passed", "Severity": "HIGH", "Status": "PASS"},
					{"ID": "DS-0002", "Title": "failed", "Severity": "HIGH", "Status": "FAIL"}
				]
			}]
		}`)

		Expect(err).ToNot(HaveOccurred())
		Expect(report.Findings).To(HaveLen(1))
		Expect(report.Findings[0].TemplateID).To(Equal("DS-0002"))
		Expect(report.Stats().Total).To(Equal(float64(2)))
		Expect(report.Stats().Matched).To(Equal(float64(1)))
	})

	It("refuses a status it does not recognise rather than guessing", func() {
		_, err := parse(`{
			"SchemaVersion": 2, "Results": [{
				"Target": "Dockerfile", "Class": "config",
				"Misconfigurations": [{"ID": "DS-0002", "Status": "MAYBE"}]
			}]
		}`)

		Expect(err).To(MatchError(ContainSubstring(`unknown status "MAYBE"`)))
	})

	It("falls back to the inventory id when trivy named no artifact", func() {
		report, err := parse(`{
			"SchemaVersion": 2, "Results": [{
				"Target": "credentials", "Class": "secret",
				"Secrets": [{"RuleID": "generic", "Severity": "HIGH", "StartLine": 1}]
			}]
		}`)

		Expect(err).ToNot(HaveOccurred())
		Expect(report.Findings[0].Host).To(Equal(contextID))
		// With no title, the rule id is the most specific name there is.
		Expect(report.Findings[0].Name).To(Equal("generic"))
	})

	It("reports a clean scan as no findings rather than as nothing scanned", func() {
		report, err := parse(`{"SchemaVersion": 2, "ArtifactName": "sample"}`)

		Expect(err).ToNot(HaveOccurred())
		Expect(report.Findings).To(BeEmpty())
		Expect(report.Stats().Total).To(BeZero())
	})
})

var _ = Describe("a report recon cannot read", func() {
	It("refuses a schema version whose fields it does not know", func() {
		path := filepath.Join(GinkgoT().TempDir(), "report.json")
		Expect(os.WriteFile(path, []byte(`{"SchemaVersion": 3}`), 0o600)).To(Succeed())

		_, err := readReport(path, contextID)
		Expect(err).To(MatchError(ContainSubstring("schema version 3, not 2")))
	})

	It("says which file it could not parse", func() {
		path := filepath.Join(GinkgoT().TempDir(), "trivy-broken.json")
		Expect(os.WriteFile(path, []byte(`{"SchemaVersion":`), 0o600)).To(Succeed())

		_, err := readReport(path, contextID)
		Expect(err).To(MatchError(ContainSubstring("trivy-broken.json")))
	})
})

var _ = Describe("naming a retained report", func() {
	DescribeTable("keeps one file per context and never collides two ids on one name",
		func(id, expected string) {
			Expect(ReportFile(id)).To(Equal(expected))
		},
		Entry("a plain id", "build-artifacts", "trivy-build-artifacts.json"),
		Entry("an image reference", "ghcr.io/acme/api:1.4", "trivy-ghcr.io_2facme_2fapi_3a1.4.json"),
		// Escaped rather than replaced: "a/b" and "a_b" are different targets
		// and must not share one report.
		Entry("an id already holding the escape", "a_b", "trivy-a_5fb.json"),
	)
})
