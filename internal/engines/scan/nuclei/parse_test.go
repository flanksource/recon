package nuclei_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines/scan/nuclei"
)

func TestNuclei(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "nuclei")
}

// results are the redacted captures of real nuclei output taken before the
// TypeScript backend was removed. Parsing has to keep working against the bytes
// the tool actually produced, not against a hand-written idea of them.
func results(name string) *os.File {
	dir, err := os.Getwd()
	Expect(err).ToNot(HaveOccurred())
	for filepath.Base(dir) != "recon" {
		parent := filepath.Dir(dir)
		Expect(parent).ToNot(Equal(dir), "repo root not found")
		dir = parent
	}

	file, err := os.Open(filepath.Join(dir, "contract/snapshot/results", name))
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(file.Close)
	return file
}

func parse(name string) ([]api.Finding, error) {
	var found []api.Finding
	err := nuclei.Engine{}.Parse(results(name), func(f api.Finding) error {
		found = append(found, f)
		return nil
	})
	return found, err
}

var _ = Describe("parsing a captured scan", func() {
	var findings []api.Finding

	BeforeEach(func() {
		var err error
		findings, err = parse("safe-non-prod-20260101-000000.jsonl")
		Expect(err).ToNot(HaveOccurred())
	})

	It("reads every finding in the file", func() {
		Expect(findings).To(HaveLen(60))
	})

	It("maps a finding's fields onto the wire type", func() {
		first := findings[0]
		Expect(first.TemplateID).To(Equal("flanksource-security-headers-baseline"))
		Expect(first.Name).To(Equal("Flanksource - HTTP Security Header Baseline"))
		Expect(first.Severity).To(Equal(api.SeverityMedium))
		Expect(first.Host).To(Equal("host-2.example.test"))
		Expect(first.MatchedAt).To(Equal("https://host-2.example.test"))
		Expect(first.Tags).To(ContainElement("headers"))
		Expect(first.Timestamp).ToNot(BeEmpty())
	})

	It("carries the whole record through so the UI can render unmodelled keys", func() {
		// ScansView renders keys the Finding type does not name, so dropping
		// anything the engine reported would silently blank parts of that view.
		Expect(findings[0].Raw).To(HaveKey("curl-command"))
		Expect(findings[0].Raw).To(HaveKey("matcher-status"))
	})

	It("drops the base64 template copy attached to every finding", func() {
		for _, finding := range findings {
			Expect(finding.Raw).ToNot(HaveKey("template-encoded"))
		}
	})

	It("recognises every severity the capture contains", func() {
		bySeverity := map[api.Severity]int{}
		for _, finding := range findings {
			bySeverity[finding.Severity]++
		}
		Expect(bySeverity).To(Equal(map[api.Severity]int{
			api.SeverityCritical: 1,
			api.SeverityHigh:     1,
			api.SeverityMedium:   56,
			api.SeverityLow:      1,
			api.SeverityInfo:     1,
		}))
	})
})

var _ = Describe("parsing the edge cases", func() {
	var findings []api.Finding
	var err error

	BeforeEach(func() {
		findings, err = parse("safe-edge-20260101-000001.jsonl")
	})

	It("reports the malformed line without losing the good ones", func() {
		Expect(findings).To(HaveLen(5))
		Expect(err).ToNot(HaveOccurred(),
			"the malformed line does not open like a record, so it is a banner")
	})

	byID := func(id string) api.Finding {
		for _, finding := range findings {
			if finding.TemplateID == id {
				return finding
			}
		}
		Fail("no finding with template id " + id)
		return api.Finding{}
	}

	It("coerces a severity nuclei does not define rather than dropping the finding", func() {
		Expect(byID("edge-bad-severity").Severity).To(Equal(api.SeverityUnknown))
	})

	It("falls back to matched-at when the finding has no host", func() {
		Expect(byID("edge-host-from-matched-at").Host).To(Equal("edge-2.example.test"))
	})

	It("falls back to the url when there is no host or matched-at", func() {
		Expect(byID("edge-host-from-url").Host).To(Equal("edge-3.example.test"))
	})

	It("strips the port from a bare host:port", func() {
		Expect(byID("edge-host-port").Host).To(Equal("edge-4.example.test"))
	})

	It("names a finding by its template when info carries no name", func() {
		Expect(byID("edge-no-name").Name).To(Equal("edge-no-name"))
	})
})

var _ = Describe("parsing damaged output", func() {
	// Cancelling a run truncates whatever line nuclei was mid-write on.
	parseString := func(body string) ([]api.Finding, error) {
		var found []api.Finding
		err := nuclei.Engine{}.Parse(strings.NewReader(body), func(f api.Finding) error {
			found = append(found, f)
			return nil
		})
		return found, err
	}

	good := `{"template-id":"a","host":"h1.example.test","info":{"name":"A","severity":"high"}}`

	It("keeps the findings either side of a truncated line and reports it", func() {
		findings, err := parseString(good + "\n" + `{"template-id":"b","host":"h2` + "\n" + good)
		Expect(findings).To(HaveLen(2))
		Expect(err).To(MatchError(ContainSubstring("line 2 is not valid JSON")))
	})

	It("skips banners and blank lines silently", func() {
		findings, err := parseString("[INF] Templates loaded: 100\n\n" + good + "\n")
		Expect(findings).To(HaveLen(1))
		Expect(err).ToNot(HaveOccurred())
	})

	It("fails outright when the caller cannot accept a finding", func() {
		// A storage failure is not the engine's to absorb.
		err := nuclei.Engine{}.Parse(strings.NewReader(good), func(api.Finding) error {
			return os.ErrClosed
		})
		Expect(err).To(MatchError(os.ErrClosed))
	})
})
