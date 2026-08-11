package nuclei

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/flanksource/recon/internal/engines/scan"
)

// collector is a run's result callback: it turns the events nuclei hands back
// into the findings the runtime records and the JSONL the run leaves on disk.
//
// Nuclei calls back from its worker pool, so every field below is written from
// several goroutines at once and the callback holds the lock throughout.
type collector struct {
	sink    scan.Sink
	encoder *json.Encoder

	mu      sync.Mutex
	err     error
	skipped map[skip]int
}

// skip is a result nuclei reported without having run anything: the host it
// gave up on, and the reason it gave.
type skip struct{ host, reason string }

func newCollector(sink scan.Sink, results io.Writer) *collector {
	return &collector{
		sink:    sink,
		encoder: json.NewEncoder(results),
		skipped: map[skip]int{},
	}
}

// Event records one result event.
//
// A result whose matcher did not fire is not a finding, and neither the sink nor
// the result file gets one. Nuclei reports those in two situations: when
// matcher-status asks it to report every template it ran, and — whatever the
// configuration — once per template it would have run against a host that
// stopped answering. The second is why they are counted rather than merely
// dropped: a single dead host in a large scan is worth saying, but saying it a
// thousand times buries every real finding in the run.
func (c *collector) Event(event *output.ResultEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !event.MatcherStatus {
		if event.Error != "" {
			c.skipped[skip{host: hostOf(event), reason: event.Error}]++
		}
		return
	}

	record, finding := convert(event)
	if err := c.encoder.Encode(record); err != nil && c.err == nil {
		c.err = err
	}
	if err := c.sink.Finding(finding); err != nil && c.err == nil {
		c.err = err
	}
}

// Report logs what the run skipped, once per host and reason, and returns the
// first error that recording a finding hit.
//
// The skips are reported at the end rather than as they arrive because the count
// is the point: mid-run, "this host is unresponsive" is indistinguishable from
// the flood it is meant to replace.
func (c *collector) Report() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	skips := make([]skip, 0, len(c.skipped))
	for key := range c.skipped {
		skips = append(skips, key)
	}
	sort.Slice(skips, func(i, j int) bool {
		if skips[i].host != skips[j].host {
			return skips[i].host < skips[j].host
		}
		return skips[i].reason < skips[j].reason
	})

	for _, key := range skips {
		count := c.skipped[key]
		plural := "s"
		if count == 1 {
			plural = ""
		}
		c.sink.Log(fmt.Sprintf("[WRN] %s: %s (%d template%s)\n", key.host, key.reason, count, plural))
	}
	return c.err
}
