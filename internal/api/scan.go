package api

import "encoding/json"

// Phase is where a run has got to. The vocabulary is the UI's, not clicky's:
// the task manager supervises the process, but what the Scans tab renders comes
// from here.
type Phase string

// The vocabulary is the one the browser and the schema already use — "idle"
// rather than "queued", "done" rather than "completed". It is not clicky's task
// vocabulary and must not drift into it: the frontend switches on these strings
// and the scans table has a check constraint listing them.
const (
	PhaseIdle      Phase = "idle"
	PhaseRunning   Phase = "running"
	PhaseDone      Phase = "done"
	PhaseFailed    Phase = "failed"
	PhaseCancelled Phase = "cancelled"
)

// Phases lists every phase, in the order a run moves through them.
func Phases() []Phase {
	return []Phase{PhaseIdle, PhaseRunning, PhaseDone, PhaseFailed, PhaseCancelled}
}

// Terminal reports whether a run has stopped.
func (p Phase) Terminal() bool {
	return p == PhaseDone || p == PhaseFailed || p == PhaseCancelled
}

// Scan is one run of a scan engine over a resolved selection of endpoints.
//
// Selector is stored rather than the resolved host list alone, so "what was this
// run aimed at" survives the inventory changing underneath it — and
// EndpointCount records what that selector actually resolved to at the time.
type Scan struct {
	ID   string `json:"id"`
	Name string `json:"name"`

	Engine        string `json:"engine"`
	EngineVersion string `json:"engineVersion,omitempty"`
	Profile       string `json:"profile"`

	Selector      map[string]any `json:"selector"`
	SelectorLabel string         `json:"selectorLabel"`
	EndpointCount int            `json:"endpointCount"`

	Phase      Phase  `json:"phase"`
	StartedAt  string `json:"startedAt"`
	FinishedAt string `json:"finishedAt,omitempty"`

	Command  []string `json:"command,omitempty"`
	ExitCode *int     `json:"exitCode,omitempty"`
	Error    string   `json:"error,omitempty"`

	Findings   int            `json:"findings"`
	Severities map[string]int `json:"severities"`
	Stats      *ScanStats     `json:"stats,omitempty"`
	Hosts      []string       `json:"hosts"`
	Result     string         `json:"resultPath,omitempty"`
}

// MarshalJSON emits empty collections rather than null.
//
// Go marshals a nil slice as null where the browser expects []. The frontend
// maps over hosts and indexes severities without checking, so a null is a
// runtime error there rather than an empty list.
func (s Scan) MarshalJSON() ([]byte, error) {
	type alias Scan // shed the method set, or this recurses
	out := alias(s)
	if out.Selector == nil {
		out.Selector = map[string]any{}
	}
	if out.Severities == nil {
		out.Severities = SeverityCounts(nil)
	}
	if out.Hosts == nil {
		out.Hosts = []string{}
	}
	if out.Command == nil {
		out.Command = []string{}
	}
	return json.Marshal(out)
}

// SeverityCounts builds the per-severity map with every level present, so the
// UI can render a fixed set of columns without checking for absent keys.
func SeverityCounts(findings []Finding) map[string]int {
	counts := map[string]int{}
	for _, severity := range Severities() {
		counts[string(severity)] = 0
	}
	for _, finding := range findings {
		counts[string(finding.Severity)]++
	}
	return counts
}

// Discover is one discovery sweep over configured zones, selected inventory, or
// explicit hosts, domains, and CIDRs.
type Discover struct {
	ID      string         `json:"id"`
	Chain   string         `json:"chain"`
	Profile string         `json:"profile"`
	Input   map[string]any `json:"input"`

	RanAt      string `json:"ranAt"`
	DurationMs int    `json:"durationMs"`
	Failed     bool   `json:"failed"`
	Error      string `json:"error,omitempty"`
	Log        string `json:"log"`

	Hosts []DiscoveredHost `json:"hosts"`
}

// DiscoveredHost is one host a sweep observed.
type DiscoveredHost struct {
	Host    string   `json:"host"`
	Engines []string `json:"engines"`
	Live    bool     `json:"live"`
}

// Profile is a stored engine configuration.
type Profile struct {
	Kind   string `json:"kind"`
	Engine string `json:"engine"`
	Name   string `json:"name"`

	Config map[string]any `json:"config"`
	// Comment is the leading comment block of the YAML the previous
	// implementation preserved across edits.
	Comment string   `json:"comment,omitempty"`
	Paths   []string `json:"paths,omitempty"`

	// Intrusive is the engine's own verdict on this configuration, and Reason
	// says why. Reported so a caller gates on the same judgement the runtime
	// enforces rather than guessing from the profile's name — the alternative
	// was a client asking for confirmation on every scan of a production host,
	// including ones the server would have run without complaint.
	Intrusive bool   `json:"intrusive"`
	Reason    string `json:"reason,omitempty"`
}

// ID is the composite key, which is what an entity get takes. Colon-separated
// rather than slash-separated: this is a path segment, and a slash would make
// one id look like three.
func (p Profile) ID() string { return p.Kind + ":" + p.Engine + ":" + p.Name }
