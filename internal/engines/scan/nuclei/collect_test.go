package nuclei

import (
	"bytes"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/flanksource/recon/internal/api"
)

// recordingSink is the runtime seen from the engine's side.
type recordingSink struct {
	findings []api.Finding
	logs     []string
}

func (s *recordingSink) Finding(finding api.Finding) error {
	s.findings = append(s.findings, finding)
	return nil
}

func (s *recordingSink) Resource(api.Resource) error { return nil }

func (s *recordingSink) Stats(api.ScanStats) {}

func (s *recordingSink) Log(text string) { s.logs = append(s.logs, text) }

// unresponsive is the event nuclei emits for a host it has given up on. It
// sends one per template it would otherwise have run.
func unresponsive(host, templateID string) *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID:    templateID,
		Type:          "http",
		Host:          host,
		URL:           "https://" + host,
		MatcherStatus: false,
		Error:         "host was skipped as it was found unresponsive",
	}
}

func matched(host, templateID string) *output.ResultEvent {
	return &output.ResultEvent{
		TemplateID:    templateID,
		Type:          "http",
		Host:          host,
		URL:           "https://" + host,
		MatcherStatus: true,
	}
}

var _ = Describe("collecting a run's results", func() {
	var (
		sink      *recordingSink
		results   *bytes.Buffer
		collected *collector
	)

	BeforeEach(func() {
		sink = &recordingSink{}
		results = &bytes.Buffer{}
		collected = newCollector(sink, results)
	})

	It("records a match as a finding and as a line in the result file", func() {
		collected.Event(matched("host-1.example.test", "tls-version"))
		Expect(collected.Report()).To(Succeed())

		Expect(sink.findings).To(HaveLen(1))
		Expect(sink.findings[0].TemplateID).To(Equal("tls-version"))
		Expect(strings.Count(results.String(), "\n")).To(Equal(1))
	})

	It("excludes a result whose matcher did not fire", func() {
		// A non-match is not a finding. Recording it would put a template that
		// found nothing in front of someone reading what a scan found.
		collected.Event(&output.ResultEvent{
			TemplateID:    "no-match",
			Host:          "host-1.example.test",
			MatcherStatus: false,
		})
		Expect(collected.Report()).To(Succeed())

		Expect(sink.findings).To(BeEmpty())
		Expect(results.String()).To(BeEmpty())
	})

	It("aggregates a skipped host into one line carrying the template count", func() {
		for _, id := range []string{"tls-version", "cookie-flags", "cors-misconfig"} {
			collected.Event(unresponsive("dead.example.test", id))
		}
		Expect(collected.Report()).To(Succeed())

		Expect(sink.findings).To(BeEmpty())
		Expect(results.String()).To(BeEmpty())
		Expect(sink.logs).To(ConsistOf(
			"[WRN] dead.example.test: host was skipped as it was found unresponsive (3 templates)\n",
		))
	})

	It("reports each skipped host separately, in host order", func() {
		collected.Event(unresponsive("b.example.test", "tls-version"))
		collected.Event(unresponsive("a.example.test", "tls-version"))
		collected.Event(unresponsive("a.example.test", "cookie-flags"))
		Expect(collected.Report()).To(Succeed())

		Expect(sink.logs).To(Equal([]string{
			"[WRN] a.example.test: host was skipped as it was found unresponsive (2 templates)\n",
			"[WRN] b.example.test: host was skipped as it was found unresponsive (1 template)\n",
		}))
	})

	It("keeps the findings of a host that answered alongside one that did not", func() {
		collected.Event(matched("live.example.test", "tls-version"))
		collected.Event(unresponsive("dead.example.test", "tls-version"))
		Expect(collected.Report()).To(Succeed())

		Expect(sink.findings).To(HaveLen(1))
		Expect(sink.findings[0].Host).To(Equal("live.example.test"))
		Expect(sink.logs).To(HaveLen(1))
	})
})
