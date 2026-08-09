package api

// Phase is where a run has got to. The vocabulary is the UI's, not clicky's:
// the task manager supervises the process, but what the Scans tab renders comes
// from here.
type Phase string

const (
	PhaseQueued    Phase = "queued"
	PhaseRunning   Phase = "running"
	PhaseCompleted Phase = "completed"
	PhaseFailed    Phase = "failed"
	PhaseCancelled Phase = "cancelled"
)

// Terminal reports whether a run has stopped.
func (p Phase) Terminal() bool {
	return p == PhaseCompleted || p == PhaseFailed || p == PhaseCancelled
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

// Discover is one discovery sweep. Unlike a scan it is not aimed at a selection:
// it enumerates, and what it finds is the point.
type Discover struct {
	ID    string `json:"id"`
	Chain string `json:"chain"`

	RanAt      string `json:"ranAt"`
	DurationMs int    `json:"durationMs"`
	Failed     bool   `json:"failed"`
	Error      string `json:"error,omitempty"`
	Log        string `json:"log,omitempty"`

	// Hosts is what the sweep saw. Known is recomputed against the current
	// inventory on every read rather than stored, because a host becomes known
	// the moment someone adds it — the sweep's own record must not go stale.
	Hosts   []DiscoveredHost `json:"hosts"`
	Unknown int              `json:"unknown"`
}

// DiscoveredHost is one host a sweep observed.
type DiscoveredHost struct {
	Host    string `json:"host"`
	Engines []string `json:"engines"`
	Live    bool     `json:"live"`
	Known   bool     `json:"known"`
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
}

// ID is the composite key, which is what an entity get takes. Colon-separated
// rather than slash-separated: this is a path segment, and a slash would make
// one id look like three.
func (p Profile) ID() string { return p.Kind + ":" + p.Engine + ":" + p.Name }
