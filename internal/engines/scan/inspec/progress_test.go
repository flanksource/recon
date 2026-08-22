package inspec

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// statsSink keeps every published snapshot, because progress is a sequence
// rather than a value: the interesting assertions are what the first frame said
// before any account finished, and what the last one totals to.
type statsSink struct{ published []api.ScanStats }

func (s *statsSink) Finding(api.Finding) error { return nil }
func (s *statsSink) Stats(stats api.ScanStats) { s.published = append(s.published, stats) }
func (s *statsSink) Log(string)                {}

func (s *statsSink) last() api.ScanStats {
	GinkgoHelper()
	Expect(s.published).ToNot(BeEmpty())
	return s.published[len(s.published)-1]
}

var _ = Describe("reporting the progress of a compliance run", func() {
	var sink *statsSink

	BeforeEach(func() { sink = &statsSink{} })

	It("publishes the account count before any benchmark returns", func() {
		newProgress(sink, 3)

		Expect(sink.published).To(HaveLen(1))
		Expect(sink.last().Hosts).To(BeEquivalentTo(3))
		Expect(sink.last().Percent).To(BeZero())
	})

	// The passing assertions are most of a benchmark run and leave no finding
	// behind, so the report has no way to say "142 of 150 controls held" unless
	// they are counted here.
	It("accumulates passing assertions across accounts", func() {
		progress := newProgress(sink, 2)
		progress.account(Counts{Controls: 40, Passed: 96, Failed: 3, Skipped: 1}, 3)
		progress.account(Counts{Controls: 40, Passed: 46, Failed: 1, Errored: 2}, 1)

		stats := sink.last()
		Expect(stats.Passed).To(BeEquivalentTo(142))
		Expect(stats.PassRecorded).To(BeTrue())
		Expect(stats.Matched).To(BeEquivalentTo(4))
		Expect(stats.Errors).To(BeEquivalentTo(2))
		Expect(stats.Requests).To(BeEquivalentTo(149))
		Expect(stats.Templates).To(BeEquivalentTo(80))
		Expect(stats.Percent).To(BeEquivalentTo(100))
	})

	It("records that passes were counted even when an account passed nothing", func() {
		progress := newProgress(sink, 1)
		progress.account(Counts{Controls: 4, Failed: 4}, 4)

		Expect(sink.last().Passed).To(BeZero())
		Expect(sink.last().PassRecorded).To(BeTrue())
	})

	It("finishes at 100 even when the last account reported nothing", func() {
		progress := newProgress(sink, 2)
		progress.account(Counts{Controls: 4, Passed: 4}, 0)
		progress.done()

		Expect(sink.last().Percent).To(BeEquivalentTo(100))
	})
})
