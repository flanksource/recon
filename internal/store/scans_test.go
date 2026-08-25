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
		severities := api.SeverityCounts([]api.Finding{{DetectionFinding: detection("tls-version", "", api.SeverityHigh)}})
		row.Phase = string(api.PhaseDone)
		row.FinishedAt = &finished
		row.DurationMS = 3250
		row.ExitCode = &exitCode
		row.Stats = models.Wrap(&stats)
		row.Severities = models.Wrap(&severities)
		endpoint := nucleiEndpointResource("api.example.test")

		Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
			Scan:      row,
			Resources: []api.Resource{endpoint},
			Output: models.ScanOutput{
				Stdout: "scan output\n", Stderr: "one warning\n",
				StdoutTruncated: true, StderrTruncated: false,
			},
			Findings: []api.Finding{{
				DetectionFinding: detection("tls-version", "Deprecated TLS version", api.SeverityHigh),
				LineNo:           1, CheckID: "tls-version", Engine: "nuclei",
				Host:      "api.example.test",
				Resources: []api.ResourceRef{endpoint.Ref()},
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
		endpoint := nucleiEndpointResource("api.example.test")
		Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
			Scan:      row,
			Resources: []api.Resource{endpoint},
			Findings: []api.Finding{
				{DetectionFinding: detection("tls-version", "", api.SeverityHigh),
					LineNo: 1, CheckID: "tls-version", Engine: "nuclei", Host: "api.example.test",
					Tags: []string{"tls", "ssl"}, Resources: []api.ResourceRef{endpoint.Ref()}},
				{DetectionFinding: detection("missing-headers", "", api.SeverityInfo),
					LineNo: 2, CheckID: "missing-headers", Engine: "nuclei", Host: "api.example.test",
					Tags: []string{"headers", "misconfig"}, Resources: []api.ResourceRef{endpoint.Ref()}},
				{DetectionFinding: detection("weak-cipher", "", api.SeverityMedium),
					LineNo: 3, CheckID: "weak-cipher", Engine: "nuclei", Host: "api.example.test",
					Tags: []string{"tls", "misconfig"}, Resources: []api.ResourceRef{endpoint.Ref()}},
			},
		})).To(Succeed())

		templates := func(opts store.FindingOpts) []string {
			GinkgoHelper()
			opts.Scan = []string{row.ID}
			found, err := st.ListFindings(ctx, opts)
			Expect(err).ToNot(HaveOccurred())
			var ids []string
			for _, finding := range found {
				ids = append(ids, finding.CheckID)
			}
			return ids
		}

		Expect(templates(store.FindingOpts{Tag: []string{"tls"}})).
			To(ConsistOf("tls-version", "weak-cipher"))
		Expect(templates(store.FindingOpts{Tag: []string{"!tls"}})).
			To(ConsistOf("missing-headers"))
		Expect(templates(store.FindingOpts{Tag: []string{"misconfig", "!tls"}})).
			To(ConsistOf("missing-headers"))

		page, err := st.ListFindingsPaged(ctx, store.FindingOpts{
			Scan: []string{row.ID}, Limit: 2, Offset: 0,
			Sort: "severity", Order: "asc",
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(page.Page.Total).To(Equal(int64(3)))
		Expect(page.Data).To(HaveLen(2))
		Expect(page.Data[0].ID).To(MatchRegexp(`^[0-9a-f-]{36}$`))
		Expect([]string{page.Data[0].CheckID, page.Data[1].CheckID}).
			To(Equal([]string{"tls-version", "weak-cipher"}))

		loaded, err := st.GetFinding(ctx, page.Data[0].ID)
		Expect(err).ToNot(HaveOccurred())
		Expect(loaded).To(Equal(page.Data[0]))
		_, err = st.GetFinding(ctx, row.ID+"#1")
		Expect(err).To(MatchError(ContainSubstring("finding")))

		page, err = st.ListFindingsPaged(ctx, store.FindingOpts{
			Scan: []string{row.ID}, Limit: 2, Offset: 2,
			Sort: "severity", Order: "asc",
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(page.Data).To(HaveLen(1))
		Expect(page.Data[0].CheckID).To(Equal("missing-headers"))
	})
})

// Nothing wrote target.scan at all before this: the column, its expression index
// and the inventory's Last scan and Findings columns all existed and were always
// empty. Finalizing is the one place that knows both what a run covered and what
// it found, so it is the one place that stamps.
var _ = Describe("recording that a run covered a host", Ordered, Label("db"), func() {
	var (
		db  *dbtest.DB
		st  *store.Store
		ctx context.Context
	)

	const covered, quiet, untouched = "a.example.test", "b.example.test", "c.example.test"

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_stamp",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()

		for _, host := range []string{covered, quiet, untouched} {
			Expect(st.SaveTarget(ctx, target(host, api.ClassNonProd))).To(Succeed(), host)
		}
	})

	// finalize runs one scan over hosts and returns when it has been recorded.
	finalize := func(engine string, at time.Time, hosts []string, count bool, findings []api.Finding) string {
		GinkgoHelper()
		selector := map[string]any{"hosts": hosts}
		row, err := st.CreateScan(ctx, models.Scan{
			Name:     engine + "-" + at.Format("20060102-150405"),
			Engine:   engine,
			Profile:  "safe",
			Selector: models.Wrap(&selector), EndpointCount: len(hosts),
			Phase: string(api.PhaseRunning), StartedAt: at,
		})
		Expect(err).ToNot(HaveOccurred())

		finished := at.Add(time.Second)
		row.Phase = string(api.PhaseDone)
		row.FinishedAt = &finished
		row.DurationMS = 1000
		resources := make(map[api.ResourceKey]api.Resource)
		for i := range findings {
			endpoint := nucleiEndpointResource(findings[i].Host)
			findings[i].Resources = []api.ResourceRef{endpoint.Ref()}
			resources[endpoint.Key()] = endpoint
		}
		emitted := make([]api.Resource, 0, len(resources))
		for _, resource := range resources {
			emitted = append(emitted, resource)
		}
		Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
			Scan: row, Resources: emitted, Findings: findings, TargetIDs: hosts, CountFindings: count,
		})).To(Succeed())
		return row.ID
	}

	scanState := func(host string) api.ScanState {
		GinkgoHelper()
		document, err := st.GetTarget(ctx, host)
		Expect(err).ToNot(HaveOccurred())
		if document.Scan == nil {
			return api.ScanState{}
		}
		return *document.Scan
	}

	It("stamps every host the run covered, with what was found on each", func() {
		at := time.Date(2026, 8, 10, 14, 0, 0, 0, time.UTC)
		// A host that was named but is not in the inventory: it is skipped, not
		// invented, which is the rule the probe runner already follows.
		finalize("nuclei", at, []string{covered, quiet, "ghost.example.test"}, true, []api.Finding{
			{DetectionFinding: detection("tls-version", "", api.SeverityHigh), LineNo: 1, CheckID: "tls-version", Engine: "nuclei", Host: covered},
			{DetectionFinding: detection("weak-cipher", "", api.SeverityMedium), LineNo: 2, CheckID: "weak-cipher", Engine: "nuclei", Host: covered},
		})

		two := 2
		Expect(scanState(covered)).To(Equal(api.ScanState{
			LastScan: "2026-08-10T14:00:01Z", LastFindings: &two,
		}))

		// The point of stamping the resolved selection rather than the findings:
		// "scanned and clean" and "never scanned" are different answers, and only
		// one of them is reassuring.
		zero := 0
		Expect(scanState(quiet)).To(Equal(api.ScanState{
			LastScan: "2026-08-10T14:00:01Z", LastFindings: &zero,
		}))

		Expect(scanState(untouched)).To(Equal(api.ScanState{}))

		_, err := st.GetTarget(ctx, "ghost.example.test")
		Expect(store.IsNotFound(err)).To(BeTrue())
	})

	// A sweep finds nothing by design, so zeroing the count would erase the
	// result of the last real scan every time someone refreshed liveness.
	It("moves last scan without discarding what the last real scan found", func() {
		at := time.Date(2026, 8, 11, 9, 0, 0, 0, time.UTC)
		finalize(api.ProbeEngine, at, []string{covered}, false, nil)

		two := 2
		Expect(scanState(covered)).To(Equal(api.ScanState{
			LastScan: "2026-08-11T09:00:01Z", LastFindings: &two,
		}))
	})

	It("leaves a run that covered nothing alone", func() {
		at := time.Date(2026, 8, 11, 10, 0, 0, 0, time.UTC)
		finalize("nuclei", at, nil, true, nil)
		Expect(scanState(untouched)).To(Equal(api.ScanState{}))
	})

	// A sweep produces no findings, so the usual host list would be empty. They
	// come from its own results instead, which is what sharing the run's id
	// between the two tables buys.
	It("lists a liveness sweep's hosts from what it probed", func() {
		at := time.Date(2026, 8, 11, 11, 0, 0, 0, time.UTC)
		selector := map[string]any{"hosts": []string{covered, quiet}}
		probe := models.Probe{
			Selector: models.Wrap(&selector), Total: 2,
			Phase: string(api.PhaseRunning), RanAt: at,
		}
		Expect(st.CreateProbe(ctx, &probe)).To(Succeed())

		_, err := st.CreateScan(ctx, models.Scan{
			ID: probe.ID, Name: "probe-liveness-20260811-110000",
			Engine: api.ProbeEngine, Profile: api.ProbeProfile,
			Selector: models.Wrap(&selector), EndpointCount: 2,
			Phase: string(api.PhaseRunning), StartedAt: at,
		})
		Expect(err).ToNot(HaveOccurred())

		for _, host := range []string{quiet, covered} {
			Expect(st.SaveProbeResult(ctx, models.ProbeResultFrom(probe.ID,
				api.ProbeResult{Host: host, Up: true, StatusCode: 200}, at))).To(Succeed())
		}

		found, err := st.GetScan(ctx, probe.ID)
		Expect(err).ToNot(HaveOccurred())
		Expect(found.Hosts).To(Equal([]string{covered, quiet}))
		Expect(found.OutputCaptured).To(BeFalse(), "a sweep runs no process")
	})
})

func nucleiEndpointResource(host string) api.Resource {
	return api.Resource{
		Provider: "nuclei", Scope: host, UID: host,
		Kind: api.KindEndpoint, Type: "url", Name: host,
		TargetID: host,
	}
}
