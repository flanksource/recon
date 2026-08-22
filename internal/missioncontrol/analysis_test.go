package missioncontrol_test

import (
	"testing"
	"time"

	dutymodels "github.com/flanksource/duty/models"
	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/missioncontrol"
)

func TestMissionControl(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "MissionControl")
}

// configID stands in for a catalog config item the resolver matched.
var configID = uuid.MustParse("3f2a1c4e-0000-4000-8000-000000000001")

func nucleiScan() api.Scan {
	return api.Scan{
		ID: "01JSCAN", Engine: "nuclei", Profile: "safe",
		StartedAt: "2026-08-10T12:00:00", FinishedAt: "2026-08-10T12:00:20",
	}
}

func tlsFinding() api.Finding {
	return api.Finding{
		ScanID: "01JSCAN", LineNo: 4, TargetID: "api.example.test",
		TemplateID: "tls-version", Name: "TLS 1.0 accepted", Severity: api.SeverityHigh,
		Host: "api.example.test", MatchedAt: "https://api.example.test:443",
		Timestamp:   "2026-08-10T12:00:11Z",
		Remediation: "Disable TLS 1.0 on the listener",
		Reference:   []string{"https://example.test/tls"},
		Tags:        []string{"tls", "baseline"},
		Raw:         map[string]any{"matcher-status": true},
	}
}

var _ = Describe("finding to insight", func() {
	It("carries the finding's identity, evidence and remediation onto the insight", func() {
		analysis, err := missioncontrol.Analysis(nucleiScan(), tlsFinding(), configID)

		Expect(err).ToNot(HaveOccurred())
		Expect(analysis.ConfigID).To(Equal(configID))
		Expect(analysis.Analyzer).To(Equal("tls-version"))
		Expect(analysis.Summary).To(Equal("TLS 1.0 accepted"))
		Expect(analysis.Status).To(Equal("open"))
		Expect(analysis.Severity).To(Equal(dutymodels.SeverityHigh))
		Expect(analysis.AnalysisType).To(Equal(dutymodels.AnalysisTypeSecurity))
		Expect(analysis.Source).To(Equal("recon/nuclei"))
		Expect(analysis.Message).To(ContainSubstring("Disable TLS 1.0 on the listener"))
		Expect(analysis.Message).To(ContainSubstring("https://example.test/tls"))
		Expect(analysis.Analysis).To(HaveKeyWithValue("scan_id", "01JSCAN"))
		Expect(analysis.Analysis).To(HaveKeyWithValue("engine", "nuclei"))
		Expect(analysis.Analysis).To(HaveKeyWithValue("matched_at", "https://api.example.test:443"))
		Expect(analysis.Analysis).To(HaveKeyWithValue("finding_id", "01JSCAN#4"))
		Expect(analysis.Analysis).To(HaveKeyWithValue("raw", map[string]any{"matcher-status": true}))
	})

	// The engine's own timestamp is when the thing was seen; the run's clock is
	// only when the run happened.
	It("observes at the engine's timestamp, falling back to the run's clock", func() {
		withStamp, err := missioncontrol.Analysis(nucleiScan(), tlsFinding(), configID)
		Expect(err).ToNot(HaveOccurred())
		Expect(withStamp.LastObserved.UTC()).To(Equal(time.Date(2026, 8, 10, 12, 0, 11, 0, time.UTC)))

		undated := tlsFinding()
		undated.Timestamp = ""
		withoutStamp, err := missioncontrol.Analysis(nucleiScan(), undated, configID)
		Expect(err).ToNot(HaveOccurred())
		Expect(*withoutStamp.LastObserved).
			To(Equal(time.Date(2026, 8, 10, 12, 0, 20, 0, time.Local)))
		Expect(withoutStamp.FirstObserved).To(Equal(withoutStamp.LastObserved))
	})

	It("rejects an engine with no analysis type rather than filing it as security", func() {
		scan := nucleiScan()
		scan.Engine = "zap"

		_, err := missioncontrol.Analysis(scan, tlsFinding(), configID)

		Expect(err).To(MatchError(ContainSubstring(`engine "zap"`)))
	})

	DescribeTable("engine decides what kind of question the insight answers",
		func(engine string, expected dutymodels.AnalysisType) {
			scan := nucleiScan()
			scan.Engine = engine

			analysis, err := missioncontrol.Analysis(scan, tlsFinding(), configID)

			Expect(err).ToNot(HaveOccurred())
			Expect(analysis.AnalysisType).To(Equal(expected))
		},
		Entry("nuclei probes for weaknesses", "nuclei", dutymodels.AnalysisTypeSecurity),
		Entry("trivy probes for weaknesses", "trivy", dutymodels.AnalysisTypeSecurity),
		Entry("prowler checks a benchmark", "prowler", dutymodels.AnalysisTypeCompliance),
		Entry("inspec checks a benchmark", "inspec", dutymodels.AnalysisTypeCompliance),
	)

	DescribeTable("severity maps onto Mission Control's ladder",
		func(reported api.Severity, expected dutymodels.Severity) {
			finding := tlsFinding()
			finding.Severity = reported

			analysis, err := missioncontrol.Analysis(nucleiScan(), finding, configID)

			Expect(err).ToNot(HaveOccurred())
			Expect(analysis.Severity).To(Equal(expected))
			Expect(analysis.Analysis).To(HaveKeyWithValue("recon_severity", string(reported)))
		},
		Entry("critical", api.SeverityCritical, dutymodels.SeverityCritical),
		Entry("high", api.SeverityHigh, dutymodels.SeverityHigh),
		Entry("medium", api.SeverityMedium, dutymodels.SeverityMedium),
		Entry("low", api.SeverityLow, dutymodels.SeverityLow),
		Entry("info", api.SeverityInfo, dutymodels.SeverityInfo),
		// Mission Control has no `unknown` rung. Landing on info keeps the
		// finding; recon_severity keeps what the engine actually said.
		Entry("unknown has no upstream rung", api.SeverityUnknown, dutymodels.SeverityInfo),
	)
})

var _ = Describe("insight identity", func() {
	// Re-uploading a run must update the insight it wrote last time rather than
	// stack a second copy beside it: Mission Control upserts on the primary key.
	It("is the same for the same finding on the same config", func() {
		Expect(missioncontrol.AnalysisID(configID, tlsFinding())).
			To(Equal(missioncontrol.AnalysisID(configID, tlsFinding())))
	})

	It("differs when the analyzer, the location or the config differs", func() {
		base := missioncontrol.AnalysisID(configID, tlsFinding())

		elsewhere := tlsFinding()
		elsewhere.MatchedAt = "https://api.example.test:8443"
		other := tlsFinding()
		other.TemplateID = "weak-cipher"
		otherConfig := uuid.MustParse("3f2a1c4e-0000-4000-8000-000000000002")

		Expect(missioncontrol.AnalysisID(configID, elsewhere)).ToNot(Equal(base))
		Expect(missioncontrol.AnalysisID(configID, other)).ToNot(Equal(base))
		Expect(missioncontrol.AnalysisID(otherConfig, tlsFinding())).ToNot(Equal(base))
	})

	// The name and severity are what a re-scan is most likely to reword. If they
	// fed the id, every such run would orphan the previous insight.
	It("ignores fields a re-scan may reword", func() {
		reworded := tlsFinding()
		reworded.Name = "TLS 1.0 is accepted by the listener"
		reworded.Severity = api.SeverityCritical

		Expect(missioncontrol.AnalysisID(configID, reworded)).
			To(Equal(missioncontrol.AnalysisID(configID, tlsFinding())))
	})
})
