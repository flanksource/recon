package inspec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/ocsf"
)

func TestInspec(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "inspec")
}

// account is the project the fixture was produced against. Everything the
// report says about a finding is scoped to one account, so it is a parameter
// here rather than a literal repeated in each assertion.
const account = "example-project"

// load reads the fixture: an exec-json document whose profile metadata, control
// ids, tag names, impact values and code_desc phrasing are taken from the real
// GoogleCloudPlatform/inspec-gcp-cis-benchmark controls, so the mapping is
// driven by the shapes the tool actually emits rather than by a convenient
// idea of them.
func load() ExecJSON {
	dir, err := os.Getwd()
	Expect(err).ToNot(HaveOccurred())
	for filepath.Base(dir) != "recon" {
		parent := filepath.Dir(dir)
		Expect(parent).ToNot(Equal(dir), "repo root not found")
		dir = parent
	}

	body, err := os.ReadFile(filepath.Join(dir, "contract/snapshot/results/inspec-gcp-cis.json"))
	Expect(err).ToNot(HaveOccurred())

	var report ExecJSON
	Expect(json.Unmarshal(body, &report)).To(Succeed())
	return report
}

// find returns the finding for one control, which is how each assertion below
// addresses the one case it is about.
func find(findings []api.Finding, control string) api.Finding {
	for _, finding := range findings {
		if finding.CheckID == control {
			return finding
		}
	}
	Fail("no finding for control " + control)
	return api.Finding{}
}

// remediationDesc reads the advice off a finding, nil-safe: OCSF models the
// prose and the references as one object, and a control offering neither has no
// object at all rather than an empty one.
func remediationDesc(finding api.Finding) string {
	if finding.Remediation == nil {
		return ""
	}
	return finding.Remediation.Desc
}

// assertion decodes one evidence entry. The assertions a control failed are
// json_t payloads rather than modelled attributes, because what an rspec
// matcher reports is the profile's own shape and OCSF has no name for it.
func assertion(entry ocsf.Evidences) map[string]any {
	GinkgoHelper()
	var decoded map[string]any
	Expect(json.Unmarshal(entry.Data, &decoded)).To(Succeed())
	return decoded
}

var _ = Describe("an InSpec report", func() {
	var report ExecJSON

	BeforeEach(func() { report = load() })

	Describe("Count", func() {
		It("tallies every assertion by status", func() {
			// Counted per result, not per control: the fixture's first control
			// has one failure and one pass, which a per-control tally would
			// collapse into a single verdict.
			Expect(report.Count()).To(Equal(Counts{
				Controls: 5,
				Passed:   1,
				Failed:   3,
				Skipped:  1,
				Errored:  1,
			}))
		})
	})

	Describe("Findings", func() {
		var findings []api.Finding

		BeforeEach(func() { findings = report.Findings(account) })

		It("reports only the results that need acting on", func() {
			// Three failures and one error. The pass and the skip are counted
			// and retained in the artifact, but a findings list that included
			// them would bury the four that matter under the ones that do not.
			Expect(findings).To(HaveLen(4))

			var ids []string
			for _, finding := range findings {
				ids = append(ids, finding.CheckID)
			}
			Expect(ids).To(ConsistOf(
				"cis-gcp-1.4-iam", "cis-gcp-2.2-logging",
				"cis-gcp-3.1-networking", "cis-gcp-6.1-databases",
			))
		})

		It("maps a failure onto the whole finding", func() {
			// Asserted as one structure rather than field by field, so a field
			// that stops being populated fails here rather than silently going
			// untested. The assertions are checked separately, below: they are
			// an opaque payload rather than modelled attributes.
			finding := find(findings, "cis-gcp-1.4-iam")
			finding.Evidences = nil

			started, err := time.Parse(time.RFC3339, "2026-08-20T09:41:02+02:00")
			Expect(err).ToNot(HaveOccurred())

			tags := []string{
				"profile:inspec-gcp-cis-benchmark",
				"cis_gcp:1.4", "cis_level:1", "cis_scored", "cis_version:4.0",
				"nist:AC-2", "nist:AC-3", "project:example-project",
			}

			Expect(finding).To(Equal(api.Finding{
				DetectionFinding: ocsf.DetectionFinding{
					ClassUID:    ocsf.ClassUID,
					CategoryUID: ocsf.CategoryUID,
					ActivityID:  ocsf.ActivityIDCreate,
					TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
					SeverityID:  ocsf.SeverityIDMedium,
					StatusID:    ocsf.StatusIDNew,
					Time:        started.UnixMilli(),
					FindingInfo: &ocsf.FindingInfo{
						UID:   "cis-gcp-1.4-iam",
						Title: "[IAM] Ensure that there are only GCP-managed service account keys for each service account",
						Desc:  "User managed service account should not have user managed keys.",
						Types: tags,
					},
					// No profile declared: inspec audits whatever it was pointed
					// at and reports no cloud identity of its own, so it must not
					// be held to naming one.
					Metadata: &ocsf.Metadata{
						Version:   ocsf.Version,
						EventCode: "cis-gcp-1.4-iam",
						Product: &ocsf.Product{
							Name:       EngineName,
							VendorName: api.Vendor,
							Version:    "4.0.0-0",
						},
					},
					Remediation: &ocsf.Remediation{
						Desc: "Anyone who has access to the keys will be able to access resources through the service account.",
						References: []string{
							"https://www.cisecurity.org/benchmark/google_cloud_computing_platform/",
							"https://cloud.google.com/iam/docs/understanding-service-accounts",
						},
					},
				},
				CheckID:   "cis-gcp-1.4-iam",
				Engine:    EngineName,
				Host:      account,
				MatchedAt: "[example-project] Service Account: builder@example-project.iam.gserviceaccount.com should not have user-managed keys",
				Tags:      tags,
				Resources: []api.ResourceRef{accountResource(account).Ref()},
			}))
		})

		// One finding per control, its N failing assertions as evidence. A
		// control is the thing a profile names, a mute rule matches and the
		// ledger tracks; one finding per rspec assertion made the same control
		// fork into as many identities as it had describe blocks.
		It("collapses a control's failing assertions into one finding", func() {
			// The fixture's first control asserts twice and fails once, so a
			// collapse that kept the passing assertion would show two.
			finding := find(findings, "cis-gcp-1.4-iam")

			Expect(finding.Evidences).To(HaveLen(1))
			Expect(assertion(finding.Evidences[0])).To(Equal(map[string]any{
				"status":    StatusFailed,
				"profile":   "inspec-gcp-cis-benchmark",
				"code_desc": "[example-project] Service Account: builder@example-project.iam.gserviceaccount.com should not have user-managed keys",
				"message":   `expected ["USER_MANAGED", "SYSTEM_MANAGED"] not to include "USER_MANAGED"`,
			}))
		})

		// OCSF's evidences object requires at least one of a named set of
		// attributes, and `name` is not among them — an entry carrying only the
		// assertion's prose would be invalid, which is the shape this would
		// otherwise take.
		It("gives every evidence entry an attribute the schema counts", func() {
			for _, finding := range findings {
				for _, entry := range finding.Evidences {
					Expect(entry.Data).ToNot(BeEmpty(),
						"an entry with only a name does not satisfy at_least_one")
				}
				Expect(ocsf.Validate(finding.DetectionFinding)).To(Succeed())
			}
		})

		It("carries an errored control through as a finding", func() {
			// A control that could not run is not a control that passed. A
			// permission error means that part of the account went unaudited,
			// which someone has to see.
			finding := find(findings, "cis-gcp-3.1-networking")

			Expect(assertion(finding.Evidences[0])).To(HaveKeyWithValue("status", StatusError))
			Expect(finding.SeverityLevel()).To(Equal(api.SeverityCritical))
		})

		It("keeps what the assertion actually reported", func() {
			finding := find(findings, "cis-gcp-2.2-logging")

			Expect(assertion(finding.Evidences[0])).
				To(HaveKeyWithValue("profile", "inspec-gcp-cis-benchmark"))
			// The rspec message is the only place that says what was actually
			// wrong, and no modelled OCSF attribute is the right home for it.
			Expect(assertion(finding.Evidences[0])).
				To(HaveKeyWithValue("message", "expected [] not to be empty"))
		})

		DescribeTable("prefers the description that says how to fix the control",
			func(control, expected string) {
				Expect(remediationDesc(find(findings, control))).To(Equal(expected))
			},
			// Profiles disagree about the label: InSpec's docs say "fix", the
			// CIS profiles write prose under "rationale". Reading only one would
			// show nothing for half the corpus.
			Entry("a fix description wins", "cis-gcp-2.2-logging",
				"Create an aggregated export sink at the organization level with an empty filter."),
			Entry("rationale is the fallback", "cis-gcp-1.4-iam",
				"Anyone who has access to the keys will be able to access resources through the service account."),
			Entry("neither present leaves it empty", "cis-gcp-3.1-networking", ""),
		)

		It("reads a reference from whichever field the profile used", func() {
			// InSpec permits ref, url and uri, and profiles use all three.
			Expect(find(findings, "cis-gcp-2.2-logging").Remediation.References).
				To(Equal([]string{"https://cloud.google.com/logging/docs/export"}))
			Expect(find(findings, "cis-gcp-3.1-networking").Remediation.References).
				To(Equal([]string{"https://cloud.google.com/vpc/docs/vpc"}))
		})

		It("drops a duplicated reference", func() {
			// CIS controls commonly cite the benchmark page from several refs.
			Expect(find(findings, "cis-gcp-1.4-iam").Remediation.References).To(HaveLen(2))
		})

		It("omits a tag whose marker is false", func() {
			// Filtering on cis_scored should find the scored controls, not
			// every control that mentions scoring.
			Expect(find(findings, "cis-gcp-2.2-logging").Tags).ToNot(ContainElement("cis_scored"))
			Expect(find(findings, "cis-gcp-1.4-iam").Tags).To(ContainElement("cis_scored"))
		})

		It("renders a numeric tag without a decimal point", func() {
			// JSON decodes every number as a float, so the obvious spelling
			// tags a CIS level as "cis_level:1e+00".
			Expect(find(findings, "cis-gcp-3.1-networking").Tags).To(ContainElement("cis_level:2"))
		})
	})

	Describe("Severity", func() {
		DescribeTable("maps InSpec's impact onto the severity ladder",
			func(impact float64, expected api.Severity) {
				Expect(Severity(impact)).To(Equal(expected))
			},
			// The values InSpec converts its named impacts to.
			Entry("none", 0.0, api.SeverityInfo),
			Entry("low", 0.3, api.SeverityLow),
			Entry("medium", 0.5, api.SeverityMedium),
			Entry("high", 0.7, api.SeverityHigh),
			Entry("critical", 0.9, api.SeverityCritical),

			// The band edges. Each is the lowest impact that reads as the band
			// above, which is where an inclusive/exclusive slip would show.
			Entry("just under low is none", 0.009, api.SeverityInfo),
			Entry("the bottom of low", 0.01, api.SeverityLow),
			Entry("just under medium", 0.39, api.SeverityLow),
			Entry("the bottom of medium", 0.4, api.SeverityMedium),
			Entry("just under high", 0.69, api.SeverityMedium),
			Entry("just under critical", 0.89, api.SeverityHigh),
			Entry("the top", 1.0, api.SeverityCritical),
		)
	})

	Describe("a control with no results", func() {
		It("produces no findings and no panic", func() {
			// InSpec emits a control with an empty results array when its
			// resource enumerated nothing — a project with no service accounts
			// produces exactly this.
			empty := ExecJSON{Profiles: []Profile{{
				Name:     "inspec-gcp-cis-benchmark",
				Controls: []Control{{ID: "cis-gcp-1.4-iam", Impact: 0.5}},
			}}}

			Expect(empty.Findings(account)).To(BeEmpty())
			Expect(empty.Count()).To(Equal(Counts{Controls: 1}))
		})
	})

	Describe("a control with no title", func() {
		It("falls back to the control id", func() {
			// A finding that names nothing cannot be acted on, and a profile is
			// not obliged to set a title.
			untitled := ExecJSON{Profiles: []Profile{{
				Name: "custom",
				Controls: []Control{{
					ID:      "cis-gcp-9.9-custom",
					Impact:  0.5,
					Results: []Result{{Status: StatusFailed, CodeDesc: "something failed"}},
				}},
			}}}

			Expect(untitled.Findings(account)[0].FindingInfo.Title).To(Equal("cis-gcp-9.9-custom"))
		})
	})
})
