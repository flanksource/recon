package models_test

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

var _ = Describe("projecting a probe run onto the wire", func() {
	ranAt := time.Date(2026, 8, 11, 9, 30, 15, 0, time.Local)
	selector := map[string]any{"class": "non-prod"}

	running := models.Probe{
		ID:       "01JPROBE",
		Selector: models.Wrap(&selector),
		Total:    12,
		Phase:    string(api.PhaseRunning),
		RanAt:    ranAt,
	}

	// The dialog polls this while the sweep is still going, so a run that has
	// not finished has to project as cleanly as one that has.
	It("describes a run that is still going without inventing an end", func() {
		run := running.Document(nil, models.ProbeCounts{Live: 3, Updated: 4}, "class non-prod")

		Expect(run).To(Equal(api.ProbeRun{
			ID:            "01JPROBE",
			Selector:      map[string]any{"class": "non-prod"},
			SelectorLabel: "class non-prod",
			Phase:         api.PhaseRunning,
			RanAt:         "2026-08-11T09:30:15",
			Total:         12,
			Live:          3,
			Updated:       4,
			Results:       []api.ProbeResult{},
		}))
	})

	// `selector` and `results` are read straight into a table and a summary line
	// in the browser, and null is not what either of them can render.
	It("never leaves the browser a null where it expects a collection", func() {
		run := models.Probe{Phase: string(api.PhaseDone)}.Document(nil, models.ProbeCounts{}, "")

		Expect([]any{run.Selector, run.Results}).To(Equal([]any{
			map[string]any{}, []api.ProbeResult{},
		}))
	})

	It("renders both timestamps as local wall clock, so the list sorts as strings", func() {
		finishedAt := ranAt.Add(49 * time.Second)
		finished := running
		finished.Phase = string(api.PhaseDone)
		finished.FinishedAt = &finishedAt
		finished.DurationMS = 49000

		run := finished.Document(nil, models.ProbeCounts{}, "class non-prod")

		Expect([]string{run.RanAt, run.FinishedAt}).To(Equal([]string{
			"2026-08-11T09:30:15", "2026-08-11T09:31:04",
		}))
	})
})

var _ = Describe("storing what one host answered", func() {
	probedAt := time.Date(2026, 8, 11, 9, 30, 16, 0, time.Local)

	It("round-trips a host that answered", func() {
		result := api.ProbeResult{
			Host:           "api.example.test",
			URL:            "https://api.example.test",
			Up:             true,
			StatusCode:     200,
			ResponseTimeMs: 125,
			IP:             "192.0.2.10",
			ContentType:    "text/html",
			Updated:        true,
		}

		row := models.ProbeResultFrom("01JPROBE", result, probedAt)

		Expect(row.ProbeID).To(Equal("01JPROBE"))
		result.ProbedAt = "2026-08-11T09:30:16"
		Expect(row.Document()).To(Equal(result))
	})

	// A host that did not answer is the point of the sweep, not an absence of
	// data: the error is what the run has to be able to show.
	It("round-trips a host that did not answer", func() {
		result := api.ProbeResult{
			Host:           "gone.example.test",
			ResponseTimeMs: 3000,
			Error:          "connection refused",
			Failure:        api.FailureRefused,
			Updated:        true,
			ProbedAt:       "2026-08-11T09:30:16",
		}

		Expect(models.ProbeResultFrom("01JPROBE", result, probedAt).Document()).
			To(Equal(result))
	})

	// Distinguishing "no response at all" from "the server answered 0" matters
	// for the Status column, which shows an em dash for the first.
	It("keeps a missing status code out of the column rather than storing zero", func() {
		row := models.ProbeResultFrom("01JPROBE", api.ProbeResult{
			Host: "gone.example.test", Error: "connection refused",
		}, probedAt)

		Expect(row.StatusCode).To(BeNil())
		Expect(row.URL).To(BeNil())
		Expect(row.IP).To(BeNil())
		Expect(row.Document().StatusCode).To(BeZero())
	})

	// The classification is what the inventory badges and the failure filter
	// reads, so it has to survive the trip through the column rather than being
	// recoverable only by re-reading the message.
	It("keeps a host that answered free of a failure kind", func() {
		row := models.ProbeResultFrom("01JPROBE", api.ProbeResult{
			Host: "api.example.test", Up: true, StatusCode: 200,
		}, probedAt)

		Expect(row.Failure).To(BeNil())
		Expect(row.Document().Failure).To(Equal(api.FailureNone))
	})

	// A probe reads whatever the far end sent. Postgres accepts NUL bytes in
	// neither text nor jsonb, and one binary error string would otherwise abort
	// the write for that host — see the finding scrubbing specs.
	It("scrubs bytes Postgres cannot store out of every string it keeps", func() {
		row := models.ProbeResultFrom("01JPROBE", api.ProbeResult{
			Host:        "host\x00",
			URL:         "https://host\x00/",
			IP:          "192.0.2.10\x00",
			ContentType: "text/html\x00",
			Error:       "unexpected \x00 in response",
		}, probedAt)

		Expect([]string{row.Host, *row.URL, *row.IP, *row.ContentType, *row.Error}).
			To(Equal([]string{
				"host�", "https://host�/", "192.0.2.10�",
				"text/html�", "unexpected � in response",
			}))
	})
})
