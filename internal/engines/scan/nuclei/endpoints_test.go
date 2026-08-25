package nuclei

import (
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// A sink that only remembers what it was given.
type endpointSink struct{ resources []api.Resource }

func (s *endpointSink) Finding(api.Finding) error { return nil }
func (s *endpointSink) Resource(resource api.Resource) error {
	s.resources = append(s.resources, resource)
	return nil
}
func (s *endpointSink) Stats(api.ScanStats) {}
func (s *endpointSink) Log(string)          {}

// Recording the endpoints a run was pointed at, not the ones it found something
// on.
//
// nuclei writes a finding only where a template matched, so an estate derived
// from findings holds exactly the broken half of it. "Nothing matched here" and
// "this was never scanned" are different facts, and the input file is the only
// place the first one exists.
var _ = Describe("the endpoints a nuclei run examined", func() {
	write := func(lines string) string {
		GinkgoHelper()
		path := filepath.Join(GinkgoT().TempDir(), "targets.txt")
		Expect(os.WriteFile(path, []byte(lines), 0o644)).To(Succeed())
		return path
	}

	It("records one resource per endpoint, whatever the run found", func() {
		sink := &endpointSink{}
		path := write("https://api.example.test/v1\nhttps://api.example.test/admin\n")

		Expect(emitEndpoints(path, sink)).To(Succeed())

		Expect(sink.resources).To(HaveLen(2))
		Expect(sink.resources[0].UID).To(Equal("https://api.example.test/v1"))
		Expect(sink.resources[0].Kind).To(Equal(api.KindEndpoint))
		Expect(sink.resources[0].ExternalIDs).To(ContainElement("https://api.example.test/v1"))
		// Two paths on one host are two subjects grouped by one account.
		Expect(sink.resources[0].Scope).To(Equal("api.example.test"))
		Expect(sink.resources[1].Scope).To(Equal("api.example.test"))
	})

	// A matcher engine asserts nothing about what it did not match, so a nuclei
	// resource carries no verdicts — and nothing it reports can ever resolve an
	// earlier finding. Recording a pass here would silently close findings on
	// the strength of a template that simply did not fire.
	It("claims no verdicts, because a template that matched nothing did not pass", func() {
		sink := &endpointSink{}

		Expect(emitEndpoints(write("https://api.example.test/\n"), sink)).To(Succeed())

		Expect(sink.resources[0].Passed).To(BeEmpty())
		Expect(sink.resources[0].Suppressed).To(BeEmpty())
	})

	It("records a repeated endpoint once", func() {
		sink := &endpointSink{}
		path := write("https://api.example.test/\n\nhttps://api.example.test/\n  \n")

		Expect(emitEndpoints(path, sink)).To(Succeed())

		Expect(sink.resources).To(HaveLen(1), "blank lines and duplicates are not endpoints")
	})

	// Recon resolves every endpoint to a full URL before nuclei sees one, so a
	// bare host is malformed input. It is still addressed rather than dropped:
	// a resource nobody can name is worse than an oddly-scoped one.
	It("keeps an endpoint it cannot parse rather than dropping it", func() {
		sink := &endpointSink{}

		Expect(emitEndpoints(write("api.example.test\n"), sink)).To(Succeed())

		Expect(sink.resources).To(HaveLen(1))
		Expect(sink.resources[0].UID).To(Equal("api.example.test"))
		Expect(sink.resources[0].Key().Validate()).To(Succeed())
	})

	It("reports a missing input rather than silently examining nothing", func() {
		Expect(emitEndpoints(filepath.Join(GinkgoT().TempDir(), "absent"), &endpointSink{})).
			To(MatchError(ContainSubstring("read scan input")))
	})
})
