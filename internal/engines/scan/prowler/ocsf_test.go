package prowler

import (
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/configdb"
	"github.com/flanksource/recon/internal/ocsf"
)

var _ = Describe("Prowler OCSF output", func() {
	It("normalizes actionable records and preserves their complete source", func() {
		report, err := readOCSF(filepath.Join("testdata", "findings.ocsf.json"), "target-gcp", "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Stats).To(Equal(api.ScanStats{
			Requests:     4,
			Total:        4,
			Percent:      100,
			Matched:      2,
			Hosts:        2,
			Templates:    4,
			Passed:       1,
			PassRecorded: true,
		}))
		Expect(report.Findings).To(HaveLen(2))

		gcp := report.Findings[0]
		unmapped := gcp.Unmapped
		gcp.Unmapped = nil

		stamped, err := time.Parse(time.RFC3339, "2026-08-20T10:00:00Z")
		Expect(err).ToNot(HaveOccurred())

		tags := []string{
			"category:identity",
			"category:privilege",
			"compliance:CIS:1.3",
			"provider:gcp",
			"resource-type:IAMPolicy",
			"service:iam",
		}

		Expect(gcp).To(Equal(api.Finding{
			DetectionFinding: ocsf.DetectionFinding{
				ClassUID:     ocsf.ClassUID,
				CategoryUID:  ocsf.CategoryUID,
				ActivityID:   ocsf.ActivityIDCreate,
				TypeUID:      ocsf.TypeUID(ocsf.ActivityIDCreate),
				SeverityID:   ocsf.SeverityIDHigh,
				Status:       "New",
				StatusID:     ocsf.StatusIDNew,
				StatusCode:   "FAIL",
				StatusDetail: "roles/editor is granted to user@example.com",
				Time:         stamped.UnixMilli(),
				RiskDetails:  "Primitive roles grant broad permissions.",
				FindingInfo: &ocsf.FindingInfo{
					UID:   "gcp_iam_primitive_roles",
					Title: "Ensure primitive roles are not used",
					Desc:  "The project allows primitive roles.",
					Types: tags,
				},
				// prowler audits a cloud account, so it declares the profile
				// that makes cloud.provider required of it — the reason the
				// other three engines declare none.
				Metadata: &ocsf.Metadata{
					Version:   ocsf.Version,
					EventCode: "gcp_iam_primitive_roles",
					Profiles:  []string{api.ProfileCloud},
					Product: &ocsf.Product{
						Name:       EngineName,
						VendorName: api.Vendor,
					},
				},
				Cloud: &ocsf.Cloud{
					Provider: "gcp",
					Account:  &ocsf.Account{UID: "example-project", Name: "example-project"},
				},
				Remediation: &ocsf.Remediation{
					Desc:       "Replace primitive roles with predefined roles.",
					References: []string{"https://example.com/gcp/iam"},
				},
			},
			TargetID:  "target-gcp",
			CheckID:   "gcp/gcp_iam_primitive_roles",
			Engine:    EngineName,
			Host:      "example-project",
			MatchedAt: "projects/example-project/roles/editor",
			Tags:      tags,
			Resources: []api.ResourceRef{{
				Provider: "gcp",
				Scope:    "example-project",
				UID:      "projects/example-project/roles/editor",
				Name:     "user@example.com",
				Type:     "IAMPolicy",
				Service:  "iam",
			}},
		}))
		// What prowler reported that OCSF has no name for goes to OCSF's own
		// escape hatch, rather than a verbatim copy of the whole record.
		Expect(unmapped).To(HaveKey("compliance"))
		Expect(unmapped).ToNot(HaveKey("finding_info"),
			"an attribute the schema models must not also be dumped in unmapped")

		kubernetes := report.Findings[1]
		Expect(kubernetes.Host).To(Equal("production"))
		Expect(kubernetes.TargetID).To(Equal("target-gcp"))
		Expect(kubernetes.CheckID).To(Equal("gcp/k8s_manual_admission_policy"))
		// prowler's status code has a column of its own now. It used to share
		// matcher_name with nuclei's matcher, inspec's result status and trivy's
		// record class — four meanings, one column.
		Expect(kubernetes.StatusCode).To(Equal("MANUAL"))
		// The lifecycle keys on this rather than on the engine's status code,
		// which means whatever that engine means by it.
		Expect(kubernetes.Verdict).To(Equal(api.VerdictManual))
	})

	// A passing check leaves no finding behind, so without a count of them a
	// clean audit and an audit that never ran look identical in the report.
	It("counts a passing check rather than only dropping it", func() {
		path := filepath.Join(GinkgoT().TempDir(), "passes.ocsf.json")
		record := func(code, check string) string {
			return `{"status":"New","status_code":"` + code + `","metadata":{"event_code":"` + check + `"},` +
				`"finding_info":{"title":"Check"},"unmapped":{"provider":"gcp","provider_uid":"example"}}`
		}
		body := []byte("[" + record("PASS", "a") + "," + record("PASS", "b") + "," + record("FAIL", "c") + "]")
		Expect(os.WriteFile(path, body, 0o644)).To(Succeed())

		report, err := readOCSF(path, "target", "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Stats.Passed).To(BeEquivalentTo(2))
		Expect(report.Stats.Matched).To(BeEquivalentTo(1))
		Expect(report.Stats.PassRecorded).To(BeTrue())
	})

	// Zero passes and "nobody counted" are different facts, and only the flag
	// separates them — a report that inferred a 0% pass rate from the count
	// alone would be reporting on the engine rather than on the account.
	It("records that passes were counted even when none passed", func() {
		path := filepath.Join(GinkgoT().TempDir(), "none.ocsf.json")
		body := []byte(`[{"status":"New","status_code":"FAIL","metadata":{"event_code":"a"},` +
			`"finding_info":{"title":"Check"},"unmapped":{"provider":"gcp","provider_uid":"example"}}]`)
		Expect(os.WriteFile(path, body, 0o644)).To(Succeed())

		report, err := readOCSF(path, "target", "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Stats.Passed).To(BeZero())
		Expect(report.Stats.PassRecorded).To(BeTrue())
	})

	// A check that fails against several resources names all of them. Only the
	// first used to survive, so the rest left no trace anywhere in recon.
	It("keeps every resource a record names, not only the first", func() {
		path := filepath.Join(GinkgoT().TempDir(), "many.ocsf.json")
		body := []byte(`[{"status":"New","status_code":"FAIL","metadata":{"event_code":"bucket_public"},` +
			`"finding_info":{"title":"Bucket is public"},"unmapped":{"provider":"gcp","provider_uid":"example"},` +
			`"resources":[` +
			`{"uid":"bucket-a","name":"logs","type":"storage.googleapis.com/Bucket","region":"eu","group":{"name":"storage"}},` +
			`{"uid":"bucket-b","name":"backups","type":"storage.googleapis.com/Bucket","region":"us"}]}]`)
		Expect(os.WriteFile(path, body, 0o644)).To(Succeed())

		report, err := readOCSF(path, "target", "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Findings).To(HaveLen(1))
		Expect(report.Findings[0].Resources).To(Equal([]api.ResourceRef{
			{Provider: "gcp", Scope: "example", UID: "bucket-a", Name: "logs", Type: "storage.googleapis.com/Bucket", Region: "eu", Service: "storage"},
			{Provider: "gcp", Scope: "example", UID: "bucket-b", Name: "backups", Type: "storage.googleapis.com/Bucket", Region: "us"},
		}))
		// MatchedAt still names the first, because it is a display string and
		// widening it would change what every stored mute rule matches.
		Expect(report.Findings[0].MatchedAt).To(Equal("bucket-a"))
	})

	// The reason passes are read at all. Only the failures used to leave a
	// trace, so a resource nothing was wrong with was invisible and "is this
	// bucket clean" had no answer.
	It("records a resource for a check that passed", func() {
		path := filepath.Join(GinkgoT().TempDir(), "passing.ocsf.json")
		body := []byte(`[{"status":"New","status_code":"PASS","metadata":{"event_code":"bucket_public"},` +
			`"finding_info":{"title":"Bucket is not public"},"unmapped":{"provider":"gcp"},` +
			`"cloud":{"provider":"gcp","account":{"uid":"example-project","name":"Example"}},` +
			`"resources":[{"uid":"logs","name":"logs","type":"storage.googleapis.com/Bucket",` +
			`"region":"eu","group":{"name":"storage"}}]}]`)
		Expect(os.WriteFile(path, body, 0o644)).To(Succeed())

		report, err := readOCSF(path, "target", "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Findings).To(BeEmpty())

		resources := report.Resources()
		Expect(resources).To(HaveLen(1))
		Expect(resources[0].UID).To(Equal("logs"))
		Expect(resources[0].Scope).To(Equal("example-project"))
		Expect(resources[0].Kind).To(Equal(api.KindCloudResource))
		Expect(resources[0].Region).To(Equal("eu"))
		// The pass is what a later run resolves a finding from.
		Expect(resources[0].Passed).To(ConsistOf("gcp/bucket_public"))
		// And the identity Mission Control's catalog would hold it under.
		Expect(resources[0].ConfigType).To(Equal("GCP::Bucket"))
		Expect(resources[0].ExternalIDs).To(ConsistOf("logs"))
	})

	// Prowler names the project itself when a check has nothing more specific to
	// point at, typing it with whichever service the check belongs to. Four such
	// checks would otherwise mint four rows for one project.
	It("collapses the account's own pseudo-resources onto one row", func() {
		path := filepath.Join(GinkgoT().TempDir(), "account.ocsf.json")
		account := `"cloud":{"provider":"gcp","account":{"uid":"example-project","name":"Example","type":"GCP Account"}}`
		body := []byte(`[` +
			`{"status":"New","status_code":"PASS","metadata":{"event_code":"apikeys_key_exists"},` +
			`"finding_info":{"title":"A"},` + account + `,` +
			`"resources":[{"uid":"example-project","name":"example-project","type":"apikeys.googleapis.com/Key"}]},` +
			`{"status":"New","status_code":"FAIL","metadata":{"event_code":"project_labels"},` +
			`"finding_info":{"title":"B"},` + account + `,` +
			`"resources":[{"uid":"example-project","name":"example-project","type":"compute.googleapis.com/Project"}]}` +
			`]`)
		Expect(os.WriteFile(path, body, 0o644)).To(Succeed())

		report, err := readOCSF(path, "target", "gcp")
		Expect(err).ToNot(HaveOccurred())

		resources := report.Resources()
		Expect(resources).To(HaveLen(1))
		Expect(resources[0].Kind).To(Equal(api.KindAccount))
		Expect(resources[0].Type).To(Equal("GCP Account"))
		Expect(resources[0].ConfigType).ToNot(Equal(configdb.ConfigType("gcp", "apikeys.googleapis.com/Key")))
		Expect(resources[0].Name).To(Equal("Example"))
		Expect(resources[0].Passed).To(ConsistOf("gcp/apikeys_key_exists"))
	})

	It("rejects an unknown status instead of silently dropping it", func() {
		path := filepath.Join(GinkgoT().TempDir(), "unknown.ocsf.json")
		body := []byte(`[{"status":"New","status_code":"ERROR","metadata":{"event_code":"check"},"finding_info":{"title":"Check"},"unmapped":{"provider":"gcp","provider_uid":"example"},"resources":[{"uid":"example"}]}]`)
		Expect(os.WriteFile(path, body, 0o644)).To(Succeed())

		_, err := readOCSF(path, "target", "gcp")
		Expect(err).To(MatchError(ContainSubstring(`unknown status_code "ERROR"`)))
	})

	It("rejects a report that cannot identify its check", func() {
		path := filepath.Join(GinkgoT().TempDir(), "invalid.ocsf.json")
		body := []byte(`[{"status":"New","status_code":"FAIL","finding_info":{"title":"Untyped"},"unmapped":{"provider":"gcp","provider_uid":"example"}}]`)
		Expect(os.WriteFile(path, body, 0o644)).To(Succeed())

		_, err := readOCSF(path, "target", "gcp")
		Expect(err).To(MatchError(ContainSubstring("metadata.event_code is required")))
	})

	It("rejects trailing JSON after the report array", func() {
		path := filepath.Join(GinkgoT().TempDir(), "trailing.ocsf.json")
		body := []byte(`[{
			"status":"New","status_code":"PASS","metadata":{"event_code":"check"},
			"unmapped":{"provider":"gcp","provider_uid":"example"}
		}] {}`)
		Expect(os.WriteFile(path, body, 0o644)).To(Succeed())

		_, err := readOCSF(path, "target", "gcp")
		Expect(err).To(MatchError(ContainSubstring("trailing JSON value")))
	})
})
