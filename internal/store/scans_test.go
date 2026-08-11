package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/flanksource/commons-db/dbtest"
	"github.com/lib/pq"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("scan execution evidence", Ordered, Label("db"), func() {
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
			Name:        "recon_scans",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
		DeferCleanup(func() {
			Expect(db.Gorm().Exec(`DELETE FROM scans`).Error).To(Succeed())
		})
	})

	It("keeps bounded process output out of listings and loads it with one scan", func() {
		started := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
		selector := map[string]any{"hosts": []string{"api.example.test"}}
		row, err := st.CreateScan(ctx, models.Scan{
			Name: "nuclei-safe-20260810-120000", Engine: "nuclei", Profile: "safe",
			Selector: models.Wrap(&selector), EndpointCount: 3,
			Phase: string(api.PhaseRunning), StartedAt: started,
		})
		Expect(err).ToNot(HaveOccurred())

		command := []string{"/opt/recon/bin/nuclei", "-target", "api.example.test", "-stats"}
		row.Command = pq.StringArray(command)
		Expect(st.UpdateScan(ctx, row)).To(Succeed())

		finished := started.Add(3250 * time.Millisecond)
		exitCode := 0
		stats := api.ScanStats{Requests: 40, Total: 60, Percent: 66.7, Matched: 1, Templates: 12}
		severities := api.SeverityCounts([]api.Finding{{Severity: api.SeverityHigh}})
		row.Phase = string(api.PhaseDone)
		row.FinishedAt = &finished
		row.DurationMS = 3250
		row.ExitCode = &exitCode
		row.Stats = models.Wrap(&stats)
		row.Severities = models.Wrap(&severities)

		Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
			Scan: row,
			Output: models.ScanOutput{
				Stdout: "scan output\n", Stderr: "one warning\n",
				StdoutTruncated: true, StderrTruncated: false,
			},
			Findings: []api.Finding{{
				TemplateID: "tls-version", Name: "Deprecated TLS version",
				Severity: api.SeverityHigh, Host: "api.example.test",
			}},
		})).To(Succeed())

		listed, err := st.ListScans(ctx, store.ScanOpts{})
		Expect(err).ToNot(HaveOccurred())
		Expect(listed).To(HaveLen(1))
		Expect(struct {
			DurationMS     int64
			Command        []string
			OutputCaptured bool
			Stdout, Stderr string
		}{
			listed[0].DurationMS, listed[0].Command, listed[0].OutputCaptured,
			listed[0].Stdout, listed[0].Stderr,
		}).To(Equal(struct {
			DurationMS     int64
			Command        []string
			OutputCaptured bool
			Stdout, Stderr string
		}{3250, command, false, "", ""}))

		detail, err := st.GetScan(ctx, row.ID)
		Expect(err).ToNot(HaveOccurred())
		Expect(struct {
			DurationMS                       int64
			OutputCaptured                   bool
			Stdout, Stderr                   string
			StdoutTruncated, StderrTruncated bool
			Findings                         int
		}{
			detail.DurationMS, detail.OutputCaptured, detail.Stdout, detail.Stderr,
			detail.StdoutTruncated, detail.StderrTruncated, detail.Findings,
		}).To(Equal(struct {
			DurationMS                       int64
			OutputCaptured                   bool
			Stdout, Stderr                   string
			StdoutTruncated, StderrTruncated bool
			Findings                         int
		}{3250, true, "scan output\n", "one warning\n", true, false, 1}))
	})

	// The findings list is the other surface the tri-state tag control drives.
	// It reaches a different table through the same predicate, so the wiring is
	// worth pinning even though the predicate itself is proven on targets.
	It("includes and excludes findings by tag", func() {
		started := time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)
		selector := map[string]any{"hosts": []string{"api.example.test"}}
		row, err := st.CreateScan(ctx, models.Scan{
			Name: "nuclei-static-20260810-130000", Engine: "nuclei", Profile: "static",
			Selector: models.Wrap(&selector), EndpointCount: 1,
			Phase: string(api.PhaseRunning), StartedAt: started,
		})
		Expect(err).ToNot(HaveOccurred())

		finished := started.Add(time.Second)
		exitCode := 0
		row.Phase = string(api.PhaseDone)
		row.FinishedAt = &finished
		row.DurationMS = 1000
		row.ExitCode = &exitCode
		Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
			Scan: row,
			Findings: []api.Finding{
				{TemplateID: "tls-version", Host: "api.example.test",
					Severity: api.SeverityHigh, Tags: []string{"tls", "ssl"}},
				{TemplateID: "missing-headers", Host: "api.example.test",
					Severity: api.SeverityInfo, Tags: []string{"headers", "misconfig"}},
				{TemplateID: "weak-cipher", Host: "api.example.test",
					Severity: api.SeverityMedium, Tags: []string{"tls", "misconfig"}},
			},
		})).To(Succeed())

		templates := func(opts store.FindingOpts) []string {
			GinkgoHelper()
			opts.Scan = []string{row.ID}
			found, err := st.ListFindings(ctx, opts)
			Expect(err).ToNot(HaveOccurred())
			var ids []string
			for _, finding := range found {
				ids = append(ids, finding.TemplateID)
			}
			return ids
		}

		Expect(templates(store.FindingOpts{Tag: []string{"tls"}})).
			To(ConsistOf("tls-version", "weak-cipher"))
		Expect(templates(store.FindingOpts{Tag: []string{"!tls"}})).
			To(ConsistOf("missing-headers"))
		Expect(templates(store.FindingOpts{Tag: []string{"misconfig", "!tls"}})).
			To(ConsistOf("missing-headers"))
	})
})
