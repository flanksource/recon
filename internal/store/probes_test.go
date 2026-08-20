package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("liveness sweep records", Ordered, Label("db"), func() {
	var (
		db  *dbtest.DB
		st  *store.Store
		ctx context.Context
	)

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_probes",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
	})

	AfterEach(func() {
		Expect(db.Gorm().Exec(`DELETE FROM probes`).Error).To(Succeed())
	})

	// start records a running sweep the way the runner does: before any traffic.
	start := func(total int, selector map[string]any) models.Probe {
		GinkgoHelper()
		row := models.Probe{
			Selector: models.Wrap(&selector), Total: total,
			TimeoutMS: 5000, Concurrency: 10, FollowRedirects: true,
			RanAt: time.Now(),
		}
		Expect(st.CreateProbe(ctx, &row)).To(Succeed())
		Expect(row.ID).ToNot(BeEmpty())
		return row
	}

	save := func(row models.Probe, host string, up, updated bool) {
		GinkgoHelper()
		Expect(st.SaveProbeResult(ctx, models.ProbeResultFrom(row.ID, api.ProbeResult{
			Host: host, URL: "https://" + host, Up: up, StatusCode: 200,
			ResponseTimeMs: 12, Updated: updated,
		}, time.Now()))).To(Succeed())
	}

	finish := func(row models.Probe, phase api.Phase) {
		GinkgoHelper()
		finished := time.Now()
		row.Phase = string(phase)
		row.FinishedAt = &finished
		row.DurationMS = 1200
		Expect(st.FinishProbe(ctx, row)).To(Succeed())
	}

	It("is readable while the sweep is still running", func() {
		// The whole reason results are written per host: the dialog and the
		// inventory refresh both read a run that has not finished.
		row := start(3, map[string]any{"class": []string{"non-prod"}})
		save(row, "one.example.test", true, true)

		running, err := st.GetProbe(ctx, row.ID)
		Expect(err).ToNot(HaveOccurred())
		Expect(running.Phase).To(Equal(api.PhaseRunning))
		Expect(running.Total).To(Equal(3), "the denominator is known up front")
		Expect(running.Results).To(HaveLen(1), "and the numerator grows as hosts finish")
		Expect(running.Live).To(Equal(1))
	})

	It("counts what answered and what was written back", func() {
		row := start(3, nil)
		save(row, "up-and-stored.example.test", true, true)
		save(row, "up-not-stored.example.test", true, false)
		save(row, "down.example.test", false, true)
		finish(row, api.PhaseDone)

		run, err := st.GetProbe(ctx, row.ID)
		Expect(err).ToNot(HaveOccurred())
		Expect([]any{run.Phase, run.Live, run.Updated, len(run.Results)}).
			To(Equal([]any{api.PhaseDone, 2, 2, 3}))
		Expect(run.DurationMs).To(Equal(1200))
		Expect(run.FinishedAt).ToNot(BeEmpty())
	})

	It("renders the selector back into the phrase the UI shows", func() {
		row := start(1, map[string]any{"class": []string{"non-prod"}})

		run, err := st.GetProbe(ctx, row.ID)
		Expect(err).ToNot(HaveOccurred())
		Expect(run.SelectorLabel).To(Equal("class non-prod"))
	})

	It("keeps results out of the listing but not their counts", func() {
		// A sweep covers the whole estate; a listing that carried every result
		// would be megabytes on a page nobody asked for that detail on.
		row := start(2, nil)
		save(row, "one.example.test", true, true)
		save(row, "two.example.test", false, true)
		finish(row, api.PhaseDone)

		listed, err := st.ListProbes(ctx, store.ProbeOpts{})
		Expect(err).ToNot(HaveOccurred())
		Expect(listed).To(HaveLen(1))
		Expect(listed[0].Results).To(BeEmpty())
		Expect([]any{listed[0].Total, listed[0].Live, listed[0].Updated}).To(Equal([]any{2, 1, 2}))
	})

	It("orders sweeps newest first", func() {
		older := start(1, nil)
		Expect(db.Gorm().Exec(`UPDATE probes SET ran_at = ran_at - interval '1 hour'`).Error).To(Succeed())
		newer := start(1, nil)

		listed, err := st.ListProbes(ctx, store.ProbeOpts{})
		Expect(err).ToNot(HaveOccurred())
		Expect([]string{listed[0].ID, listed[1].ID}).To(Equal([]string{newer.ID, older.ID}))
	})

	It("finds the sweeps that touched one host", func() {
		touched := start(1, nil)
		save(touched, "wanted.example.test", true, true)
		other := start(1, nil)
		save(other, "unwanted.example.test", true, true)

		listed, err := st.ListProbes(ctx, store.ProbeOpts{Host: []string{"wanted.example.test"}})
		Expect(err).ToNot(HaveOccurred())
		Expect(listed).To(HaveLen(1))
		Expect(listed[0].ID).To(Equal(touched.ID))
	})

	It("selects by phase", func() {
		running := start(1, nil)
		done := start(1, nil)
		finish(done, api.PhaseDone)

		listed, err := st.ListProbes(ctx, store.ProbeOpts{Phase: []string{string(api.PhaseRunning)}})
		Expect(err).ToNot(HaveOccurred())
		Expect(listed).To(HaveLen(1))
		Expect(listed[0].ID).To(Equal(running.ID))
	})

	It("answers one host's history newest first, across sweeps", func() {
		first := start(1, nil)
		save(first, "tracked.example.test", true, true)
		second := start(1, nil)
		save(second, "tracked.example.test", false, true)

		history, err := st.ProbeHistory(ctx, "tracked.example.test", 10)
		Expect(err).ToNot(HaveOccurred())
		Expect(history).To(HaveLen(2))
		Expect(history[0].Up).To(BeFalse(), "the most recent answer comes first")
		Expect(history[1].Up).To(BeTrue())
	})

	It("re-probing a host in one sweep overwrites rather than conflicts", func() {
		row := start(1, nil)
		save(row, "flapping.example.test", false, true)
		save(row, "flapping.example.test", true, true)

		run, err := st.GetProbe(ctx, row.ID)
		Expect(err).ToNot(HaveOccurred())
		Expect(run.Results).To(HaveLen(1))
		Expect(run.Results[0].Up).To(BeTrue())
	})

	It("takes its results with it when it is deleted", func() {
		row := start(1, nil)
		save(row, "one.example.test", true, true)

		Expect(db.Gorm().Exec(`DELETE FROM probes WHERE id = ?`, row.ID).Error).To(Succeed())

		var remaining int64
		Expect(db.Gorm().Raw(`SELECT COUNT(*) FROM probe_results WHERE probe_id = ?`, row.ID).
			Scan(&remaining).Error).To(Succeed())
		Expect(remaining).To(BeZero())
	})

	It("refuses to finish a sweep in a phase that is not terminal", func() {
		// Finishing is what stops the dialog polling. A run left "running" after
		// being finished would poll forever.
		row := start(1, nil)
		row.Phase = string(api.PhaseRunning)

		Expect(st.FinishProbe(ctx, row)).To(MatchError(ContainSubstring("is not terminal")))
	})

	It("reports a sweep nobody has", func() {
		_, err := st.GetProbe(ctx, "01JZZZZZZZZZZZZZZZZZZZZZZZ")
		Expect(store.IsNotFound(err)).To(BeTrue(), "%v", err)
	})
})
