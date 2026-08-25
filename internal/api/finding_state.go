package api

// FindingState is the current verdict on one check against one resource.
//
// It is the answer to a question the findings table cannot answer: two runs of
// the same profile an hour apart reported 65 failures and then 49, and nothing
// in either run's rows says which sixteen problems were fixed. A finding is
// evidence from one run; a state is what is true now.
//
// Rows exist for checks that have only ever passed. That is not padding — 141
// of one report's 190 verdicts are passes, and "this bucket has been checked
// for public access forty times and passed every time" is the compliance
// posture, which has nowhere else to live.
type FindingState struct {
	ID         string `json:"id"`
	ResourceID string `json:"resourceId"`
	Engine     string `json:"engine"`

	// CheckID is the finding's template id, e.g. gcp/apikeys_key_exists.
	CheckID string `json:"checkId"`

	// Status is open, resolved, muted or manual.
	Status   string `json:"status"`
	Severity string `json:"severity"`

	// Reason says how a check stopped being open, which is not the same claim
	// in every case: `passed` is a fact — the check ran again and passed —
	// while `resource-absent` and `not-reported` are inferences from a covering
	// run's silence.
	Reason string `json:"reason,omitempty"`

	// MutedBy names the rule that accepted this, while one does. A value rather
	// than a substring of Reason, so deleting the rule can reopen exactly what it
	// was suppressing.
	MutedBy string `json:"mutedBy,omitempty"`

	FirstSeen string `json:"firstSeen"`

	// LastSeen is the last verdict of any kind. A stale value does not mean
	// resolved; it means nobody re-checked, which is why an engine that reports
	// no passes leaves its findings open with an ageing timestamp instead of
	// quietly closing them.
	LastSeen   string `json:"lastSeen"`
	LastOpenAt string `json:"lastOpenAt,omitempty"`
	ResolvedAt string `json:"resolvedAt,omitempty"`

	FirstScanID string `json:"firstScanId,omitempty"`
	LastScanID  string `json:"lastScanId,omitempty"`

	// OpenScanID is the run that most recently opened it and does not move
	// while it stays open, so "failing since" survives a re-run.
	OpenScanID string `json:"openScanId,omitempty"`

	// FindingID is the evidence while open, empty once it is not.
	FindingID string `json:"findingId,omitempty"`

	// Occurrences counts runs that reported it failing, not findings.
	Occurrences int       `json:"occurrences"`
	TargetID    string    `json:"targetId,omitempty"`
	Resource    *Resource `json:"resource,omitempty"`
	Finding     *Finding  `json:"finding,omitempty"`
}

func (s FindingState) GetID() string   { return s.ID }
func (s FindingState) GetName() string { return s.CheckID }

// Open reports a check that currently fails.
func (s FindingState) Open() bool { return s.Status == StatusOpen }
