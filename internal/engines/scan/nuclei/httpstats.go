package nuclei

import (
	"sync"

	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/output/stats/waf"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/nucleierr"
	"github.com/projectdiscovery/utils/errkit"

	"github.com/flanksource/recon/internal/api"
)

// wafScanLimit bounds how much of a response the firewall fingerprints are
// matched against.
//
// Detection runs around a hundred regexes over the text, and a scan issues tens
// of thousands of responses — matching whole bodies would make collecting the
// statistics cost more than the scan. Every fingerprint is a header, a status
// page title or a block-page banner, all of which are at the front.
const wafScanLimit = 8 << 10

// httpStats counts what a run put on the wire.
//
// It is an output.Writer because that is the only seam nuclei calls per request
// rather than per finding: `Request` fires for every attempt including the ones
// that matched nothing, and `RequestStatsLog` for every HTTP response. Findings
// still arrive through the result callback — the SDK wraps this writer and its
// own mock writer in a MultiWriter, so both are called.
//
// Nuclei's own stats.Tracker covers the same three hooks, but keys errors by
// message text: one unreachable host contributes a distinct key per address,
// and the result is a breakdown nothing can chart. Errors are counted by
// errkit's bounded kind vocabulary here instead.
type httpStats struct {
	detector *waf.WafDetector

	mu        sync.Mutex
	requests  int
	responses int
	failed    int
	bytes     int64
	protocols map[string]int
	statuses  map[string]int
	errors    map[string]int
	wafs      map[string]int
}

var _ output.Writer = (*httpStats)(nil)

func newHTTPStats() *httpStats {
	return &httpStats{
		detector:  waf.NewWafDetector(),
		protocols: map[string]int{},
		statuses:  map[string]int{},
		errors:    map[string]int{},
		wafs:      map[string]int{},
	}
}

// Request records one attempt, whatever protocol made it.
func (h *httpStats) Request(templateID, url, requestType string, err error) {
	kind := ""
	if err != nil {
		kind = errkit.GetErrorKind(err, nucleierr.ErrTemplateLogic).String()
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.requests++
	if requestType != "" {
		h.protocols[requestType]++
	}
	if kind != "" {
		h.failed++
		h.errors[kind]++
	}
}

// RequestStatsLog records one HTTP response. `response` is the full text nuclei
// read, which is where both the size and any firewall fingerprint come from.
func (h *httpStats) RequestStatsLog(statusCode, response string) {
	scanned := response
	if len(scanned) > wafScanLimit {
		scanned = scanned[:wafScanLimit]
	}
	detected, found := h.detector.DetectWAF(scanned)

	h.mu.Lock()
	defer h.mu.Unlock()

	h.responses++
	h.bytes += int64(len(response))
	if statusCode != "" {
		h.statuses[statusCode]++
	}
	if found {
		h.wafs[detected]++
	}
}

// Snapshot copies the counters for a reader. The maps are copied because the
// caller publishes them while the scan keeps writing.
func (h *httpStats) Snapshot() *api.HTTPStats {
	h.mu.Lock()
	defer h.mu.Unlock()

	return &api.HTTPStats{
		Requests:    h.requests,
		Responses:   h.responses,
		Failed:      h.failed,
		Bytes:       h.bytes,
		StatusCodes: copyCounts(h.statuses),
		Protocols:   copyCounts(h.protocols),
		Errors:      copyCounts(h.errors),
		WAF:         copyCounts(h.wafs),
	}
}

func copyCounts(counts map[string]int) map[string]int {
	out := make(map[string]int, len(counts))
	for key, count := range counts {
		out[key] = count
	}
	return out
}

// The rest of output.Writer. Findings, failures and debug data all reach recon
// by other routes, so this writer only has to not interfere with them —
// ResultCount in particular must stay zero, or the MultiWriter answers with it
// instead of asking the writer that actually counted results.

func (h *httpStats) Write(*output.ResultEvent) error { return nil }

func (h *httpStats) WriteFailure(*output.InternalWrappedEvent) error { return nil }

func (h *httpStats) WriteStoreDebugData(host, templateID, eventType, data string) {}

func (h *httpStats) ResultCount() int { return 0 }

func (h *httpStats) Colorizer() *aurora.Aurora { return aurora.New(aurora.WithColors(false)) }

func (h *httpStats) Close() {}
