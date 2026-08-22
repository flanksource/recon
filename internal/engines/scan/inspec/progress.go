package inspec

import (
	"sync"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines/scan"
)

// progress reports a compliance run in the vocabulary the scan UI already
// renders.
//
// InSpec reports nothing until an account finishes, so progress moves in whole
// accounts rather than continuously. That is honest about what is knowable: the
// alternative is a bar that interpolates, which would sit at a made-up
// percentage for minutes at a time.
type progress struct {
	sink  scan.Sink
	total int

	mu       sync.Mutex
	done_    int
	stats    api.ScanStats
	controls int
}

func newProgress(sink scan.Sink, accounts int) *progress {
	p := &progress{sink: sink, total: accounts}
	// Hosts is the account count, so the run reports what it is covering before
	// the first benchmark returns.
	p.stats = api.ScanStats{Hosts: float64(accounts)}
	p.publish()
	return p
}

// account records one finished audit.
//
// Requests counts assertions rather than HTTP calls: InSpec does not report its
// API traffic, and a benchmark's unit of work is the assertion. Templates
// counts controls, which is the closest thing a benchmark has to a template.
func (p *progress) account(counts Counts, findings int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.done_++
	p.controls += counts.Controls

	p.stats.Requests += float64(counts.Passed + counts.Failed + counts.Skipped + counts.Errored)
	p.stats.Matched += float64(findings)
	p.stats.Errors += float64(counts.Errored)
	// Every assertion in a benchmark has a verdict, so the passes are counted
	// rather than inferred — an account whose controls all failed still reports
	// that a count was taken.
	p.stats.Passed += float64(counts.Passed)
	p.stats.PassRecorded = true
	p.stats.Templates = float64(p.controls)
	p.stats.Total = float64(p.total)
	p.stats.Percent = float64(p.done_) / float64(p.total) * 100

	p.publish()
}

// done marks the run complete, so a run whose last account produced no report
// still finishes at 100 rather than short of it.
func (p *progress) done() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.stats.Percent = 100
	p.publish()
}

// publish is called with the lock held.
func (p *progress) publish() { p.sink.Stats(p.stats) }
