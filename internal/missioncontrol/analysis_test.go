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
	"github.com/flanksource/recon/internal/ocsf"
)

func TestMissionControl(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "MissionControl")
}

var configID = uuid.MustParse("3f2a1c4e-0000-4000-8000-000000000001")

func nucleiScan() api.Scan {
	return api.Scan{
		ID: "01JSCAN", Engine: "nuclei", Profile: "safe", Phase: api.PhaseDone,
		StartedAt: "2026-08-10T12:00:00", FinishedAt: "2026-08-10T12:00:20",
	}
}

func tlsFinding() api.Finding {
	return api.Finding{
		DetectionFinding: ocsf.DetectionFinding{
			ClassUID:    ocsf.ClassUID,
			CategoryUID: ocsf.CategoryUID,
			ActivityID:  ocsf.ActivityIDCreate,
			TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
			SeverityID:  ocsf.SeverityIDHigh,
			Time:        1786000811000,
			FindingInfo: &ocsf.FindingInfo{
				UID:   "tls-version",
				Title: "TLS 1.0 accepted",
				Types: []string{"tls", "baseline"},
			},
			Metadata: &ocsf.Metadata{
				Version:   ocsf.Version,
				EventCode: "tls-version",
				Product:   &ocsf.Product{Name: "nuclei", VendorName: api.Vendor},
			},
			Remediation: &ocsf.Remediation{
				Desc:       "Disable TLS 1.0 on the listener",
				References: []string{"https://example.test/tls"},
			},
			Unmapped: map[string]any{"matcher-status": true},
		},
		ScanID: "01JSCAN", LineNo: 4, TargetID: "api.example.test",
		Engine: "nuclei", CheckID: "tls-version",
		Host: "api.example.test", MatchedAt: "https://api.example.test:443",
		Tags: []string{"tls", "baseline"},
	}
}

func currentState(status string) api.InsightState {
	resource := api.Resource{
		ID: "01JRESOURCE", Provider: "nuclei", Scope: "api.example.test",
		UID: "https://api.example.test", Name: "https://api.example.test",
		ExternalIDs: []string{"https://api.example.test"},
	}
	return api.InsightState{
		Resource: resource, Finding: tlsFinding(), Scan: nucleiScan(),
		State: api.FindingState{
			ID: "01JSTATE", ResourceID: resource.ID, Engine: "nuclei", CheckID: "tls-version",
			Status: status, Severity: string(api.SeverityHigh), Occurrences: 2,
			FirstSeen: "2026-08-10T12:00:11", LastSeen: "2026-08-11T12:00:11",
		},
	}
}

var _ = Describe("current state to insight", func() {
	DescribeTable("maps the complete lifecycle",
		func(state, expected string) {
			analysis, err := missioncontrol.StateAnalysis(currentState(state), configID)
			Expect(err).ToNot(HaveOccurred())
			Expect(analysis.Status).To(Equal(expected))
		},
		Entry("open", api.StatusOpen, dutymodels.AnalysisStatusOpen),
		Entry("manual remains actionable", api.StatusManual, dutymodels.AnalysisStatusOpen),
		Entry("resolved closes", api.StatusResolved, dutymodels.AnalysisStatusResolved),
		Entry("muted silences", api.StatusMuted, dutymodels.AnalysisStatusSilenced),
	)

	It("uses ledger timestamps and carries resource identity", func() {
		analysis, err := missioncontrol.StateAnalysis(currentState(api.StatusResolved), configID)

		Expect(err).ToNot(HaveOccurred())
		Expect(*analysis.FirstObserved).To(Equal(time.Date(2026, 8, 10, 12, 0, 11, 0, time.Local)))
		Expect(*analysis.LastObserved).To(Equal(time.Date(2026, 8, 11, 12, 0, 11, 0, time.Local)))
		Expect(analysis.Analysis).To(HaveKeyWithValue("finding_state_id", "01JSTATE"))
		Expect(analysis.Analysis).To(HaveKey("resource"))
	})

	It("keeps one identity when evidence location and wording change", func() {
		base := currentState(api.StatusOpen)
		reworded := base
		// A fresh object, not a mutation: finding_info is a pointer, so editing
		// it in the copy would edit the original too and the spec would compare
		// a value with itself.
		reworded.Finding.FindingInfo = &ocsf.FindingInfo{
			UID: base.Finding.CheckID, Title: "Listener accepts obsolete TLS",
		}
		reworded.Finding.MatchedAt = "https://api.example.test:8443"

		Expect(missioncontrol.InsightAnalysisID(configID, base.Resource, base.State.Engine, base.State.CheckID)).
			To(Equal(missioncontrol.InsightAnalysisID(configID, reworded.Resource, reworded.State.Engine, reworded.State.CheckID)))
	})

	It("keeps separate insights for two resources rolled onto one config", func() {
		first := currentState(api.StatusOpen)
		second := currentState(api.StatusOpen)
		second.Resource.UID = "https://api.example.test/admin"

		Expect(missioncontrol.InsightAnalysisID(configID, first.Resource, first.State.Engine, first.State.CheckID)).
			ToNot(Equal(missioncontrol.InsightAnalysisID(configID, second.Resource, second.State.Engine, second.State.CheckID)))
	})
})
