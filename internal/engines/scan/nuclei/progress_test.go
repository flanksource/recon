package nuclei

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	"github.com/flanksource/recon/internal/api"
)

// recorder keeps every statistic published, so a spec can assert on the last one
// the UI would have shown rather than on an internal field.
type recorder struct {
	stats []api.ScanStats
}

func (r *recorder) Finding(api.Finding) error { return nil }
func (r *recorder) Stats(s api.ScanStats)     { r.stats = append(r.stats, s) }
func (r *recorder) Log(string)                {}

func (r *recorder) last() api.ScanStats {
	GinkgoHelper()
	Expect(r.stats).ToNot(BeEmpty(), "nothing was published")
	return r.stats[len(r.stats)-1]
}

var _ = Describe("scan progress", func() {
	var (
		sink     *recorder
		progress *progressWriter
	)

	BeforeEach(func() {
		sink = &recorder{}
		progress = newProgress(sink)
	})

	// The clock is pinned rather than slept on: these assert arithmetic, and a
	// spec that waits for real seconds to check a rate is a spec that flakes.
	elapsed := func(d time.Duration) { progress.started = time.Now().Add(-d) }

	It("publishes the totals as soon as nuclei knows them", func() {
		progress.Init(2, 344, 1398)

		Expect(sink.last()).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"Hosts":     Equal(float64(2)),
			"Templates": Equal(float64(344)),
			"Total":     Equal(float64(1398)),
			"Requests":  Equal(float64(0)),
		}))
	})

	It("reports the rate over the whole run, not since nuclei finished clustering", func() {
		// Init lands after templates are clustered and targets resolved, which on
		// a cold start is seconds in and after requests have been counted.
		// Restarting the clock there divided everything so far by a few
		// milliseconds and reported hundreds of thousands of requests a second.
		elapsed(10 * time.Second)
		progress.SetRequests(500)
		progress.Init(2, 344, 1398)
		progress.SetRequests(500)

		Expect(sink.last().RPS).To(BeNumerically("~", 100, 1))
		Expect(sink.last().Duration).To(Equal("0:10"))
	})

	It("counts a failed request as both a request and an error", func() {
		progress.Init(1, 10, 100)
		progress.IncrementFailedRequestsBy(7)

		Expect(sink.last()).To(gstruct.MatchFields(gstruct.IgnoreExtras, gstruct.Fields{
			"Requests": Equal(float64(7)),
			"Errors":   Equal(float64(7)),
		}))
	})

	It("keeps the percentage at 100 when a template outruns its estimate", func() {
		// The total is an estimate made before redirects and retries happen, so
		// requests genuinely can exceed it. A bar past 100% reads as a bug.
		progress.Init(1, 10, 100)
		progress.SetRequests(140)

		Expect(sink.last().Percent).To(Equal(float64(100)))
	})

	It("reports no percentage rather than a wrong one before the total is known", func() {
		progress.IncrementRequests()

		Expect(sink.last().Percent).To(Equal(float64(0)))
		Expect(sink.last().Requests).To(Equal(float64(1)))
	})

	DescribeTable("renders elapsed time the way the stats line did",
		func(d time.Duration, expected string) {
			elapsed(d)
			progress.Stop()
			Expect(sink.last().Duration).To(Equal(expected))
		},
		Entry("seconds", 9*time.Second, "0:09"),
		Entry("minutes", 3*time.Minute+7*time.Second, "3:07"),
		Entry("past an hour", 2*time.Hour+5*time.Minute+1*time.Second, "2:05:01"),
	)
})
