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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/httpapi"
	"github.com/flanksource/recon/internal/scan"
)

// The directory is partitioned by the day a run started, so the date is pinned
// rather than taken from the clock: a suite running over midnight would
// otherwise build one path and assert against another.
func timestamp() time.Time { return time.Date(2026, 8, 12, 9, 30, 0, 0, time.UTC) }

// stubScans answers with one run, so these specs are about the routes rather
// than about the store behind them.
type stubScans struct{ run api.Scan }

func (s stubScans) GetScan(_ context.Context, id string) (api.Scan, error) {
	if id != s.run.ID && id != s.run.Name {
		return api.Scan{}, fmt.Errorf("scan %s not found", id)
	}
	return s.run, nil
}

var _ = Describe("serving a run's retained artifacts", func() {
	var (
		suite *httptest.Server
		dir   string
	)

	serve := func(run api.Scan) {
		mux := http.NewServeMux()
		httpapi.RegisterScanFiles(mux, stubScans{run: run})
		suite = httptest.NewServer(mux)
		DeferCleanup(suite.Close)
	}

	BeforeEach(func() {
		artifacts, err := scan.NewArtifacts(GinkgoT().TempDir(), "nuclei", timestamp(), "nuclei-safe-1")
		Expect(err).ToNot(HaveOccurred())
		dir = artifacts.Dir
		Expect(artifacts.WriteFile(scan.FindingsFile, []byte(`{"template-id":"tls-version"}`+"\n"))).To(Succeed())
		Expect(artifacts.WriteFile(scan.TargetsFile, []byte("https://a.example.test\n"))).To(Succeed())
	})

	get := func(path string) *http.Response {
		GinkgoHelper()
		response, err := http.Get(suite.URL + path)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(response.Body.Close)
		return response
	}

	It("lists the directory alongside the path it is on disk", func() {
		serve(api.Scan{ID: "01", Name: "nuclei-safe-1", Result: dir})

		response := get("/api/scan/01/files")
		Expect(response.StatusCode).To(Equal(http.StatusOK))

		var listing api.ScanFiles
		Expect(json.NewDecoder(response.Body).Decode(&listing)).To(Succeed())
		Expect(listing.ScanID).To(Equal("01"))
		Expect(listing.Path).To(Equal(dir))
		Expect(listing.Files).To(HaveLen(2))
		Expect(listing.Files[0].Name).To(Equal(scan.FindingsFile))
		Expect(listing.Files[0].Size).To(BeNumerically(">", 0))
	})

	It("serves a file byte-for-byte as the engine wrote it", func() {
		serve(api.Scan{ID: "01", Name: "nuclei-safe-1", Result: dir})

		response := get("/api/scan/01/files/" + scan.FindingsFile)
		Expect(response.StatusCode).To(Equal(http.StatusOK))
		Expect(response.Header.Get("Content-Type")).To(HavePrefix("text/plain"))
		Expect(io.ReadAll(response.Body)).To(BeEquivalentTo(`{"template-id":"tls-version"}` + "\n"))
	})

	It("serves nested provider output by its relative artifact path", func() {
		nested := filepath.Join(dir, "contexts", "0001", "output")
		Expect(os.MkdirAll(nested, 0o755)).To(Succeed())
		Expect(os.WriteFile(filepath.Join(nested, "report.ocsf.json"), []byte("[]\n"), 0o644)).To(Succeed())
		serve(api.Scan{ID: "01", Name: "prowler-cis", Result: dir})

		response := get("/api/scan/01/files/contexts/0001/output/report.ocsf.json")
		Expect(response.StatusCode).To(Equal(http.StatusOK))
		Expect(io.ReadAll(response.Body)).To(BeEquivalentTo("[]\n"))
	})

	// The directory comes from the database and the name from the URL, so the
	// route must not be one `..` away from serving whatever the process can read.
	It("refuses to serve anything outside the run's own directory", func() {
		outside := filepath.Join(filepath.Dir(dir), "secrets.env")
		Expect(os.WriteFile(outside, []byte("token=hunter2\n"), 0o600)).To(Succeed())
		serve(api.Scan{ID: "01", Name: "nuclei-safe-1", Result: dir})

		for _, name := range []string{"..%2Fsecrets.env", "..", "%2Fetc%2Fpasswd"} {
			response := get("/api/scan/01/files/" + name)
			Expect(response.StatusCode).To(Equal(http.StatusNotFound), name)
			Expect(io.ReadAll(response.Body)).ToNot(ContainSubstring("hunter2"), name)
		}
	})

	It("says a run kept nothing rather than serving an empty listing", func() {
		serve(api.Scan{ID: "01", Name: "legacy-run"})

		response := get("/api/scan/01/files")
		Expect(response.StatusCode).To(Equal(http.StatusNotFound))
		Expect(io.ReadAll(response.Body)).To(ContainSubstring("kept no artifacts"))
	})

	// A pruned or moved directory is not an empty one. Answering with an empty
	// list would read as "this scan produced nothing", which is a different and
	// much more alarming fact.
	It("distinguishes a directory that is gone from one that is empty", func() {
		serve(api.Scan{ID: "01", Name: "nuclei-safe-1", Result: filepath.Join(dir, "moved-away")})

		Expect(get("/api/scan/01/files").StatusCode).To(Equal(http.StatusGone))
	})

	It("answers for a run nobody has", func() {
		serve(api.Scan{ID: "01", Name: "nuclei-safe-1", Result: dir})

		Expect(get("/api/scan/99/files").StatusCode).To(Equal(http.StatusNotFound))
	})
})
