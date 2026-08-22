package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/httpapi"
	"github.com/flanksource/recon/internal/report"
	"github.com/flanksource/recon/internal/scan"
	"github.com/flanksource/recon/internal/store"
)

// stubReportSource answers with one run and its findings, so these specs are
// about the routes rather than the database behind them.
type stubReportSource struct {
	run      api.Scan
	findings []api.Finding
	opts     *store.FindingOpts
}

func (s *stubReportSource) GetScan(_ context.Context, id string) (api.Scan, error) {
	if id != s.run.ID && id != s.run.Name {
		return api.Scan{}, fmt.Errorf("scan %s not found", id)
	}
	return s.run, nil
}

func (s *stubReportSource) ListFindings(_ context.Context, opts store.FindingOpts) ([]api.Finding, error) {
	s.opts = &opts
	return s.findings, nil
}

// stubRenderer records what it was asked to print instead of shelling out, so
// the routes are testable on a machine with no facet install.
type stubRenderer struct {
	unavailable error
	failure     error
	document    []byte
	payload     any
	format      report.Format
}

func (s *stubRenderer) Available() error { return s.unavailable }

func (s *stubRenderer) Render(_ context.Context, format report.Format, payload any) ([]byte, error) {
	s.format, s.payload = format, payload
	if s.failure != nil {
		return nil, s.failure
	}
	return s.document, nil
}

var _ = Describe("serving a run as a report", func() {
	var (
		suite    *httptest.Server
		source   *stubReportSource
		renderer *stubRenderer
	)

	run := api.Scan{
		ID:            "9f2c1a70",
		Name:          "nuclei-safe-214",
		Engine:        "nuclei",
		Profile:       "scan:nuclei:safe",
		SelectorLabel: "class prod",
		Phase:         api.PhaseDone,
		Findings:      2,
		Hosts:         []string{"a.example.test"},
	}

	BeforeEach(func() {
		source = &stubReportSource{
			run: run,
			findings: []api.Finding{
				{TemplateID: "http/tls-version", Name: "Weak TLS", Severity: api.SeverityHigh, Host: "a.example.test"},
				{TemplateID: "http/missing-hsts", Name: "No HSTS", Severity: api.SeverityLow, Host: "a.example.test"},
			},
		}
		renderer = &stubRenderer{document: []byte("%PDF-1.7 rendered")}

		mux := http.NewServeMux()
		httpapi.RegisterScanReport(mux, source, renderer)
		suite = httptest.NewServer(mux)
		DeferCleanup(suite.Close)
	})

	get := func(path string) *http.Response {
		GinkgoHelper()
		response, err := http.Get(suite.URL + path)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(response.Body.Close)
		return response
	}

	decode := func(response *http.Response) api.ScanReport {
		GinkgoHelper()
		var payload api.ScanReport
		Expect(json.NewDecoder(response.Body).Decode(&payload)).To(Succeed())
		return payload
	}

	It("serves the run and its findings as the payload the template consumes", func() {
		payload := decode(get("/api/scan/9f2c1a70/report"))

		Expect(payload.Scan.Name).To(Equal("nuclei-safe-214"))
		Expect(payload.Findings).To(HaveLen(2))
		Expect(payload.GeneratedAt).ToNot(BeEmpty())
		Expect(payload.FindingLimit).To(Equal(httpapi.ReportFindingLimit))
		Expect(payload.SourceURL).To(HaveSuffix("/scans/9f2c1a70"))
	})

	It("includes the effective scan parameters retained with the run", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(
			filepath.Join(dir, scan.ConfigFile),
			[]byte(`{"rate-limit":50,"headless":true}`),
			0o644,
		)).To(Succeed())
		source.run.Result = dir

		payload := decode(get("/api/scan/9f2c1a70/report"))

		Expect(payload.Parameters).To(Equal(map[string]any{
			"rate-limit": float64(50),
			"headless":   true,
		}))
	})

	It("rejects a malformed retained scan configuration", func() {
		dir := GinkgoT().TempDir()
		Expect(os.WriteFile(
			filepath.Join(dir, scan.ConfigFile),
			[]byte(`["rate-limit",50]`),
			0o644,
		)).To(Succeed())
		source.run.Result = dir

		response := get("/api/scan/9f2c1a70/report")

		Expect(response.StatusCode).To(Equal(http.StatusInternalServerError))
		body, err := io.ReadAll(response.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("scan 9f2c1a70 parameters"))
	})

	It("asks the store for the run's findings up to the report's own limit", func() {
		get("/api/scan/9f2c1a70/report")

		Expect(source.opts).ToNot(BeNil())
		Expect(source.opts.Scan).To(Equal([]string{"9f2c1a70"}))
		Expect(source.opts.Limit).To(Equal(httpapi.ReportFindingLimit))
	})

	It("reads the report's presentation off the query string", func() {
		payload := decode(get(
			"/api/scan/9f2c1a70/report?title=Quarterly+Review&classification=Secret" +
				"&preparedBy=Security&watermark=DRAFT&minSeverity=medium&maxDetailedFindings=25" +
				"&traffic=false&appendix=0"))

		Expect(payload.Options.Title).To(Equal("Quarterly Review"))
		Expect(payload.Options.Classification).To(Equal("Secret"))
		Expect(payload.Options.PreparedBy).To(Equal("Security"))
		Expect(payload.Options.Watermark).To(Equal("DRAFT"))
		Expect(payload.Options.MinSeverity).To(Equal(api.SeverityMedium))
		Expect(payload.Options.MaxDetailedFindings).To(Equal(25))
		Expect(payload.Options.Sections.Traffic).To(HaveValue(BeFalse()))
		Expect(payload.Options.Sections.Appendix).To(HaveValue(BeFalse()))
	})

	It("leaves every section unset when the caller toggled none, so the template prints them all", func() {
		Expect(decode(get("/api/scan/9f2c1a70/report")).Options.Sections).To(BeNil())
	})

	It("distinguishes a section turned off from one left alone", func() {
		sections := decode(get("/api/scan/9f2c1a70/report?traffic=false")).Options.Sections

		Expect(sections.Traffic).To(HaveValue(BeFalse()))
		Expect(sections.Coverage).To(BeNil())
	})

	DescribeTable("rejecting a malformed option as the caller's mistake",
		func(query string) {
			response := get("/api/scan/9f2c1a70/report?" + query)
			Expect(response.StatusCode).To(Equal(http.StatusBadRequest))
		},
		Entry("an unknown severity", "minSeverity=catastrophic"),
		Entry("a negative cap", "maxDetailedFindings=-1"),
		Entry("a non-numeric cap", "maxDetailedFindings=lots"),
		Entry("a non-boolean section", "traffic=sometimes"),
	)

	It("renders the same payload as a PDF, named after the run", func() {
		response := get("/api/scan/9f2c1a70/report.pdf")

		Expect(response.StatusCode).To(Equal(http.StatusOK))
		Expect(response.Header.Get("Content-Type")).To(Equal("application/pdf"))
		Expect(response.Header.Get("Content-Disposition")).
			To(Equal(`attachment; filename="nuclei-safe-214-report.pdf"`))
		body, err := io.ReadAll(response.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(body).To(Equal([]byte("%PDF-1.7 rendered")))

		Expect(renderer.format).To(Equal(report.FormatPDF))
		Expect(renderer.payload).To(BeAssignableToTypeOf(api.ScanReport{}))
		Expect(renderer.payload.(api.ScanReport).Findings).To(HaveLen(2))
	})

	It("renders HTML from the same route family", func() {
		response := get("/api/scan/9f2c1a70/report.html")

		Expect(response.StatusCode).To(Equal(http.StatusOK))
		Expect(response.Header.Get("Content-Type")).To(Equal("text/html; charset=utf-8"))
		Expect(renderer.format).To(Equal(report.FormatHTML))
	})

	It("answers a missing renderer as unimplemented rather than a failed export", func() {
		renderer.unavailable = report.ErrRendererUnavailable

		response := get("/api/scan/9f2c1a70/report.pdf")

		Expect(response.StatusCode).To(Equal(http.StatusNotImplemented))
		body, err := io.ReadAll(response.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("facet is not installed"))
	})

	It("still serves the JSON payload when no renderer is installed", func() {
		renderer.unavailable = report.ErrRendererUnavailable

		Expect(get("/api/scan/9f2c1a70/report").StatusCode).To(Equal(http.StatusOK))
	})

	It("reports a render failure as a bad gateway, carrying facet's own message", func() {
		renderer.failure = fmt.Errorf("facet pdf failed: exit status 1")

		response := get("/api/scan/9f2c1a70/report.pdf")

		Expect(response.StatusCode).To(Equal(http.StatusBadGateway))
		body, err := io.ReadAll(response.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(ContainSubstring("exit status 1"))
	})

	It("answers an unknown run as not found", func() {
		Expect(get("/api/scan/nope/report.pdf").StatusCode).To(Equal(http.StatusNotFound))
	})
})
