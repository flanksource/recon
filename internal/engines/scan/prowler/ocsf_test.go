package prowler

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

var _ = Describe("Prowler OCSF output", func() {
	It("normalizes actionable records and preserves their complete source", func() {
		report, err := readOCSF(filepath.Join("testdata", "findings.ocsf.json"), "target-gcp", "gcp")
		Expect(err).ToNot(HaveOccurred())
		Expect(report.Stats).To(Equal(api.ScanStats{
			Requests:  4,
			Total:     4,
			Percent:   100,
			Matched:   2,
			Hosts:     2,
			Templates: 4,
		}))
		Expect(report.Findings).To(HaveLen(2))

		gcp := report.Findings[0]
		raw := gcp.Raw
		gcp.Raw = nil
		Expect(gcp).To(Equal(api.Finding{
			TargetID:    "target-gcp",
			TemplateID:  "gcp/gcp_iam_primitive_roles",
			Name:        "Ensure primitive roles are not used",
			Severity:    api.SeverityHigh,
			Host:        "example-project",
			MatchedAt:   "projects/example-project/roles/editor",
			MatcherName: "FAIL",
			Type:        EngineName,
			Tags: []string{
				"category:identity",
				"category:privilege",
				"compliance:CIS:1.3",
				"provider:gcp",
				"resource-type:IAMPolicy",
				"service:iam",
			},
			Timestamp:   "2026-08-20T10:00:00Z",
			Remediation: "Replace primitive roles with predefined roles.",
			Reference:   []string{"https://example.com/gcp/iam"},
		}))
		Expect(raw).To(HaveKeyWithValue("risk_details", "Primitive roles grant broad permissions."))
		Expect(raw).To(HaveKey("finding_info"))

		kubernetes := report.Findings[1]
		Expect(kubernetes.Host).To(Equal("production"))
		Expect(kubernetes.TargetID).To(Equal("target-gcp"))
		Expect(kubernetes.TemplateID).To(Equal("gcp/k8s_manual_admission_policy"))
		Expect(kubernetes.MatcherName).To(Equal("MANUAL"))
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
