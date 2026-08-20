package api

// ScanStats is an engine's progress report. Every field is optional: engines
// that report nothing leave it zero, and the UI shows no progress bar rather
// than a misleading one.
type ScanStats struct {
	Requests  float64 `json:"requests"`
	Total     float64 `json:"total"`
	Percent   float64 `json:"percent"`
	RPS       float64 `json:"rps"`
	Matched   float64 `json:"matched"`
	Errors    float64 `json:"errors"`
	Hosts     float64 `json:"hosts"`
	Templates float64 `json:"templates"`
	Duration  string  `json:"duration,omitempty"`

	// HTTP is what the traffic itself looked like, when the engine reports its
	// requests individually. Absent rather than zeroed for an engine that does
	// not, so the UI can tell "nothing was sent" from "nobody counted".
	HTTP *HTTPStats `json:"http,omitempty"`
}

// HTTPStats is what a run put on the wire.
//
// It is counted from the engine's own per-request hooks rather than recovered
// from its log, so it covers every request the scan issued — which is almost
// all of them, since a request that matches nothing produces no finding and
// would otherwise leave no trace. That is the point: "the scan found nothing"
// and "the scan never got a response" look identical without it.
type HTTPStats struct {
	// Requests is what the engine attempted, Responses what came back with a
	// status line, and Failed the attempts that ended in an error. Requests is
	// not Responses + Failed: a redirect chain reads several responses for one
	// request, and protocols that are not HTTP report a request and no status.
	Requests  int   `json:"requests"`
	Responses int   `json:"responses"`
	Failed    int   `json:"failed"`
	Bytes     int64 `json:"bytes"`

	// StatusCodes counts responses by code, Protocols requests by the engine's
	// own protocol vocabulary (http, dns, ssl, javascript …), Errors failures by
	// kind, and WAF the firewalls whose fingerprints appeared in a response.
	StatusCodes map[string]int `json:"statusCodes"`
	Protocols   map[string]int `json:"protocols"`
	Errors      map[string]int `json:"errors"`
	WAF         map[string]int `json:"waf"`
}

// Empty reports that nothing was counted, which is what the UI checks before
// rendering a breakdown of no traffic at all.
func (h *HTTPStats) Empty() bool {
	return h == nil || (h.Requests == 0 && h.Responses == 0 && h.Failed == 0)
}

// ScanFile is one artifact a run left behind.
type ScanFile struct {
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	Modified string `json:"modified"`
}

// ScanFiles is a run's retained output directory and what is in it.
//
// Path is reported alongside the listing because the directory is the durable
// artifact: it outlives the process, it is what someone re-runs a tool against,
// and a download link alone does not tell them where to look on disk.
type ScanFiles struct {
	ScanID string     `json:"scanId"`
	Path   string     `json:"path"`
	Files  []ScanFile `json:"files"`
}
