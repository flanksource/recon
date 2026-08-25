package nuclei

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/flanksource/recon/internal/api"
)

func TestNuclei(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "nuclei")
}

// results are the redacted captures of real nuclei output taken before the
// TypeScript backend was removed.
//
// Nuclei is linked in now, so nothing parses this file during a scan — but it is
// still exactly the JSON encoding of the result events the engine hands us, and
// the run writes the same shape back out. Driving the mapping from the bytes the
// tool actually produced is what keeps convert honest against a hand-written
// idea of nuclei's output.
func results(name string) (events []*output.ResultEvent, rejected []string) {
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

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		event := &output.ResultEvent{}
		if err := json.Unmarshal(line, event); err != nil {
			var loose struct {
				TemplateID string `json:"template-id"`
			}
			_ = json.Unmarshal(line, &loose)
			rejected = append(rejected, loose.TemplateID)
			continue
		}
		events = append(events, event)
	}
	Expect(scanner.Err()).ToNot(HaveOccurred())
	return events, rejected
}

func convertAll(name string) []api.Finding {
	events, rejected := results(name)
	Expect(rejected).To(BeEmpty(), "every record in %s should decode", name)

	var found []api.Finding
	for _, event := range events {
		_, finding, err := convert(event)
		Expect(err).ToNot(HaveOccurred())
		found = append(found, finding)
	}
	return found
}

var _ = Describe("converting a captured scan", func() {
	var findings []api.Finding

	BeforeEach(func() {
		findings = convertAll("safe-non-prod-20260101-000000.jsonl")
	})

	It("reads every finding in the file", func() {
		Expect(findings).To(HaveLen(60))
	})

	It("maps a finding's fields onto the wire type", func() {
		first := findings[0]
		Expect(first.CheckID).To(Equal("flanksource-security-headers-baseline"))
		Expect(first.FindingInfo.Title).To(Equal("Flanksource - HTTP Security Header Baseline"))
		Expect(first.SeverityLevel()).To(Equal(api.SeverityMedium))
		Expect(first.Host).To(Equal("host-2.example.test"))
		Expect(first.MatchedAt).To(Equal("https://host-2.example.test"))
		Expect(first.Resources).To(Equal([]api.ResourceRef{
			endpointResource("https://host-2.example.test").Ref(),
		}))
		Expect(first.Tags).To(ContainElement("headers"))
		Expect(first.Time).ToNot(BeZero())
	})

	// The HTTP exchange, in the place OCSF defines for it rather than in four
	// columns of recon's own that no other engine ever filled.
	It("carries the exchange as evidence", func() {
		Expect(findings[0].Evidences).To(HaveLen(1))
		evidence := findings[0].Evidences[0]

		Expect(evidence.HTTPRequest.Args).To(HavePrefix("GET "))
		Expect(evidence.HTTPResponse.Message).To(HavePrefix("HTTP/"))
		Expect(evidence.URL.URLString).To(Equal("https://host-2.example.test"))

		var data map[string]any
		Expect(json.Unmarshal(evidence.Data, &data)).To(Succeed())
		Expect(data).To(HaveKeyWithValue("curl", ContainSubstring("curl")))
	})

	// What nuclei reported that the schema has no name for, in OCSF's own escape
	// hatch. `protocol` is the one that mattered: event.Type is "http" or "dns",
	// and it used to be written to the same column prowler wrote its engine name
	// to — so `findings.type` meant "engine" for one and "protocol" for another.
	It("puts the engine's own extras where the schema says to", func() {
		Expect(findings[0].Unmapped).To(HaveKeyWithValue("protocol", "http"))
		Expect(findings[0].Engine).To(Equal(EngineName))
	})

	// The base64 copy of the template is attached to every event and is the
	// single largest thing nuclei reports. Nothing renders it.
	It("does not carry the base64 template copy attached to every finding", func() {
		for _, finding := range findings {
			Expect(finding.Unmapped).ToNot(HaveKey("template-encoded"))
			encoded, err := json.Marshal(finding)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(encoded)).ToNot(ContainSubstring("template-encoded"))
		}
	})

	It("recognises every severity the capture contains", func() {
		bySeverity := map[api.Severity]int{}
		for _, finding := range findings {
			bySeverity[finding.SeverityLevel()]++
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

var _ = Describe("converting the edge cases", func() {
	var findings []api.Finding

	BeforeEach(func() {
		events, rejected := results("safe-edge-20260101-000001.jsonl")

		// nuclei's own decoder refuses a severity outside its vocabulary, so a
		// record carrying one never becomes a result event at all. That is the
		// engine's boundary, not ours — what matters here is that it costs one
		// record and not the file.
		Expect(rejected).To(ConsistOf("edge-bad-severity"))

		findings = nil
		for _, event := range events {
			_, finding, err := convert(event)
			Expect(err).ToNot(HaveOccurred())
			findings = append(findings, finding)
		}
	})

	byID := func(id string) api.Finding {
		for _, finding := range findings {
			if finding.CheckID == id {
				return finding
			}
		}
		Fail("no finding with template id " + id)
		return api.Finding{}
	}

	It("classifies an unset severity as unknown rather than dropping the finding", func() {
		// This is the reachable case: nuclei hands us a severity enum, and its
		// zero value means the template declared none. A finding nobody can
		// classify is still a finding.
		_, finding, err := convert(&output.ResultEvent{TemplateID: "no-severity", Host: "h.example.test"})

		Expect(err).ToNot(HaveOccurred())
		Expect(finding.SeverityLevel()).To(Equal(api.SeverityUnknown))
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
		Expect(byID("edge-no-name").FindingInfo.Title).To(Equal("edge-no-name"))
	})
})

var _ = Describe("Nuclei configuration", func() {
	It("rejects automatic technology selection when DAST removes its detection templates", func() {
		err := Engine{}.Spec().ValidateConfig(map[string]any{
			"automatic-scan": true,
			"dast":           true,
		})

		Expect(err).To(MatchError(ContainSubstring("automatic-scan cannot be combined with dast")))
	})
})
