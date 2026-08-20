package api

import "fmt"

// Failure is why a probe got no usable answer.
//
// Classified rather than left as the prober's error string: "does this host
// resolve" and "does anything listen on it" are different problems with
// different owners, and a raw `dial tcp: lookup x: no such host` can be badged
// or filtered on only by guessing at its wording.
type Failure string

const (
	// FailureNone is the absence of a failure — the host answered.
	FailureNone Failure = ""
	// FailureDNS is a name that does not resolve.
	FailureDNS Failure = "dns"
	// FailureRefused is a name that resolves to something listening to nothing.
	FailureRefused Failure = "refused"
	// FailureUnreachable is a route that does not reach the address.
	FailureUnreachable Failure = "unreachable"
	// FailureTimeout is an address that accepted the packets and never answered.
	FailureTimeout Failure = "timeout"
	// FailureTLS is a handshake or certificate the prober would not accept.
	FailureTLS Failure = "tls"
	// FailureHTTP is a host that answered with a status outside 2xx. The only
	// kind where the endpoint is up and something above the transport is wrong.
	FailureHTTP Failure = "http"
	// FailureOther is everything the classifier could not place.
	FailureOther Failure = "other"
)

// Failures lists every classified failure, roughly in the order a request meets
// them. It is the filter's vocabulary and the target schema's enum.
func Failures() []Failure {
	return []Failure{
		FailureDNS, FailureRefused, FailureUnreachable,
		FailureTimeout, FailureTLS, FailureHTTP, FailureOther,
	}
}

// ProbeEngine is what a liveness sweep records itself as in the scans table.
//
// Not a registered scan engine — nothing compiles it in and no profile
// configures it — but a sweep is a run that covered a set of hosts at a time,
// which is what that table is, and recording it there is what makes "when was
// this host last checked" one question rather than two.
const ProbeEngine = "probe"

// ProbeProfile names the only configuration a sweep has. The column is NOT NULL
// and a blank value would show up as an empty option in the profile filter.
const ProbeProfile = "liveness"

// ProbeResult is what a liveness check saw for one host.
//
// A host is tried over HTTPS and then HTTP, and this is the first answer —
// a host that redirects HTTP to HTTPS is up, and reporting the HTTP leg's
// redirect as its status would describe it worse.
type ProbeResult struct {
	Host           string `json:"host"`
	URL            string `json:"url,omitempty"`
	Up             bool   `json:"up"`
	StatusCode     int    `json:"statusCode,omitempty"`
	ResponseTimeMs int64  `json:"responseTimeMs"`
	IP             string `json:"ip,omitempty"`
	ContentType    string `json:"contentType,omitempty"`
	Error          string `json:"error,omitempty"`

	// Failure is why Error happened, in a form the inventory can badge and
	// filter on. Empty whenever the host answered.
	Failure Failure `json:"failure,omitempty"`

	// ProbedAt is when this host finished, not when the run started. A sweep of
	// the estate takes minutes, so the two are different facts and the per-host
	// one is what a target's history is ordered by.
	ProbedAt string `json:"probedAt,omitempty"`

	// Updated reports that the host's inventory record was rewritten. It is
	// false for a host that was probed but has no curated record to fold the
	// result into — inventing one is discovery's job, not a refresh's.
	Updated bool `json:"updated"`
}

// ProbeRun is one pass of liveness checks over selected inventory targets.
//
// Selector is stored rather than the resolved host list alone, so "what was
// this run aimed at" survives the inventory changing underneath it — the same
// reasoning as Scan, and Total records what that selector resolved to at the
// time.
type ProbeRun struct {
	ID string `json:"id"`

	Selector      map[string]any `json:"selector"`
	SelectorLabel string         `json:"selectorLabel"`

	Phase      Phase  `json:"phase"`
	RanAt      string `json:"ranAt"`
	FinishedAt string `json:"finishedAt,omitempty"`
	DurationMs int    `json:"durationMs"`

	// Total is how many hosts the run set out to probe, and is the denominator
	// the progress bar divides by. Results is shorter than it while the run is
	// still going — that difference is the progress.
	Total int `json:"total"`

	// Live counts the hosts that answered, and Updated the ones whose inventory
	// record was rewritten — they differ when a host is probed but not stored.
	Live    int `json:"live"`
	Updated int `json:"updated"`

	Error string `json:"error,omitempty"`

	Results []ProbeResult `json:"results"`
}

// GetID identifies the run. The listing deep-links this, and it is also the id
// of the task group the run drives, so /api/v1/tasks/{id} and
// /api/v1/probe/{id} address the same thing.
func (p ProbeRun) GetID() string { return p.ID }

// GetName summarises what the run found.
func (p ProbeRun) GetName() string {
	return fmt.Sprintf("%d of %d host(s) answered", p.Live, p.Total)
}
