package nuclei

import (
	"fmt"
	"sync"
	"time"

	nucleiprogress "github.com/projectdiscovery/nuclei/v3/pkg/progress"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines/scan"
)

// progressWriter turns nuclei's progress callbacks into scan statistics.
//
// It replaces parsing -stats-json lines out of stdout. The counters are the same
// ones nuclei's own progress bar reads, so the percentage no longer depends on
// a log line arriving intact, and Init supplies the totals up front rather than
// after the first interval — a scan reports "0 of 4,314 templates" immediately
// instead of showing an empty bar until the first stats tick.
type progressWriter struct {
	sink scan.Sink

	mu        sync.Mutex
	started   time.Time
	hosts     int64
	templates int
	total     int64
	requests  uint64
	matched   int64
	errors    int64
}

var _ nucleiprogress.Progress = (*progressWriter)(nil)

func newProgress(sink scan.Sink) *progressWriter {
	return &progressWriter{sink: sink, started: time.Now()}
}

// Init supplies the totals. It deliberately does not restart the clock: nuclei
// calls this once it has clustered templates and resolved targets, which is well
// after the run began and, on a cold start, after requests have already been
// counted. Resetting `started` here divides every request so far by a few
// milliseconds and reports a rate in the hundreds of thousands.
func (p *progressWriter) Init(hostCount int64, rulesCount int, requestCount int64) {
	p.mu.Lock()
	p.hosts, p.templates, p.total = hostCount, rulesCount, requestCount
	p.mu.Unlock()
	p.report()
}

func (p *progressWriter) AddToTotal(delta int64) {
	p.mu.Lock()
	p.total += delta
	p.mu.Unlock()
	p.report()
}

func (p *progressWriter) IncrementRequests() {
	p.mu.Lock()
	p.requests++
	p.mu.Unlock()
	p.report()
}

func (p *progressWriter) SetRequests(count uint64) {
	p.mu.Lock()
	p.requests += count
	p.mu.Unlock()
	p.report()
}

func (p *progressWriter) IncrementMatched() {
	p.mu.Lock()
	p.matched++
	p.mu.Unlock()
	p.report()
}

func (p *progressWriter) IncrementErrorsBy(count int64) {
	p.mu.Lock()
	p.errors += count
	p.mu.Unlock()
	p.report()
}

// IncrementFailedRequestsBy counts a failure as both a request and an error,
// matching nuclei's own accounting: a request that failed still happened.
func (p *progressWriter) IncrementFailedRequestsBy(count int64) {
	p.mu.Lock()
	p.requests += uint64(count)
	p.errors += count
	p.mu.Unlock()
	p.report()
}

func (p *progressWriter) Stop() { p.report() }

// report publishes a consistent snapshot. Every counter method calls it, so the
// UI sees the latest numbers without a polling interval of its own.
func (p *progressWriter) report() {
	p.mu.Lock()
	stats := api.ScanStats{
		Requests:  float64(p.requests),
		Total:     float64(p.total),
		Matched:   float64(p.matched),
		Errors:    float64(p.errors),
		Hosts:     float64(p.hosts),
		Templates: float64(p.templates),
	}
	elapsed := time.Since(p.started)
	p.mu.Unlock()

	if stats.Total > 0 {
		stats.Percent = min(stats.Requests/stats.Total*100, 100)
	}
	if seconds := elapsed.Seconds(); seconds > 0 {
		stats.RPS = stats.Requests / seconds
	}
	stats.Duration = formatDuration(elapsed)

	p.sink.Stats(stats)
}

// formatDuration renders elapsed time the way nuclei's stats line did, so the
// value the UI shows does not change format just because its source did.
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	if hours > 0 {
		return fmt.Sprintf("%d:%02d:%02d", hours, minutes, seconds)
	}
	return fmt.Sprintf("%d:%02d", minutes, seconds)
}
