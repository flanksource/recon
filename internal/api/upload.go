package api

import "encoding/json"

// Upload is what one push of a scan's findings into Mission Control did.
//
// The counts are deliberately three numbers rather than one: a finding that
// landed on the resource it is actually about and a finding that landed on the
// account containing it are both uploaded, but they are not equally useful, and
// a run where everything rolled up is a signal that the catalog does not hold
// what recon scanned.
type Upload struct {
	ScanID string `json:"scanId"`
	Engine string `json:"engine"`
	// Context is the faro context the push authenticated with, and Server the
	// Mission Control it went to — both recorded so a result is attributable
	// after the fact.
	Context string `json:"context,omitempty"`
	Server  string `json:"server,omitempty"`
	Agent   string `json:"agent"`
	DryRun  bool   `json:"dryRun,omitempty"`

	// Findings is how many were considered after the severity filter, of the
	// Total the run recorded.
	Findings int `json:"findings"`
	Total    int `json:"total"`
	Pushed   int `json:"pushed"`
	// Resolved matched the finding's own resource; RolledUp matched the cluster,
	// account or project containing it.
	Resolved int `json:"resolved"`
	RolledUp int `json:"rolledUp"`

	Configs    []UploadConfig     `json:"configs"`
	Unresolved []UploadUnresolved `json:"unresolved"`
	// Notes record the finer identities that were skipped for being ambiguous.
	Notes []string `json:"notes,omitempty"`
}

// UploadConfig is one catalog config item the upload attached insights to.
type UploadConfig struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Insights int    `json:"insights"`
	RolledUp bool   `json:"rolledUp,omitempty"`
}

// UploadUnresolved is a finding that was not uploaded because nothing in the
// catalog claims it, together with every identity that was tried. It is
// reported rather than dropped: an insight attached to the wrong config item is
// worse than one that is missing and accounted for.
type UploadUnresolved struct {
	Finding  string   `json:"finding"`
	Host     string   `json:"host,omitempty"`
	Severity Severity `json:"severity,omitempty"`
	Tried    []string `json:"tried"`
	Reason   string   `json:"reason"`
}

// MarshalJSON emits empty collections rather than null, for the same reason
// Scan does: the frontend maps over these without checking.
func (u Upload) MarshalJSON() ([]byte, error) {
	type alias Upload // shed the method set, or this recurses
	out := alias(u)
	if out.Configs == nil {
		out.Configs = []UploadConfig{}
	}
	if out.Unresolved == nil {
		out.Unresolved = []UploadUnresolved{}
	}
	return json.Marshal(out)
}
