package api

// Template is one scan template as the catalogue lists it.
//
// It exists so "which templates would this profile run" is answerable before a
// scan rather than inferred from its results. The fields are the engine's own
// metadata, normalised only in name: this is a catalogue of someone else's
// templates, and renaming their vocabulary would make it harder to match a
// finding back to what produced it.
type Template struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Engine   string `json:"engine"`
	Severity string `json:"severity"`

	// Type is the protocol the template speaks: http, dns, tcp, ssl, code and
	// so on. It is the first request block the template declares, which is what
	// the engine reports on a finding.
	Type string `json:"type"`

	Tags    []string `json:"tags"`
	Authors []string `json:"authors"`

	// Path locates the template within the installed template set, which is
	// what makes a finding traceable to a file someone can read.
	Path string `json:"path"`

	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	CVEID       string   `json:"cveId,omitempty"`
	CVSSScore   float64  `json:"cvssScore,omitempty"`

	// MaxRequests is what the template costs to run against one target. Summed
	// across a selection it is the closest estimate of a scan's size available
	// before running it.
	MaxRequests int `json:"maxRequests,omitempty"`

	// Requires names the capabilities a profile must opt into before this
	// template runs at all — enabling code or headless templates, or DAST.
	Requires []string `json:"requires,omitempty"`
}

// GetID returns the template id, which is what a finding reports and what the
// filters address.
func (t Template) GetID() string { return t.ID }

// GetName returns the template's human name.
func (t Template) GetName() string { return t.Name }

// TemplatePreview is what a profile configuration would run.
//
// Counts describe the whole selection; Templates is a sample of it, because the
// broad profiles select thousands and a preview that returned all of them would
// be the scan's inventory rather than a summary of it.
type TemplatePreview struct {
	Engine  string `json:"engine"`
	Profile string `json:"profile,omitempty"`

	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
	ByType     map[string]int `json:"byType"`
	ByTag      []TemplateTag  `json:"byTag"`

	// MaxRequests is the summed per-template request cost against a single
	// target. Templates that declare none contribute nothing, so it is a lower
	// bound.
	MaxRequests int `json:"maxRequests"`

	Templates []Template `json:"templates"`
	Truncated bool       `json:"truncated"`

	// Caveats names the reasons this count may overstate what runs — a filter
	// the preview cannot evaluate, or a requirement that depends on the machine
	// doing the scanning. Reported rather than hidden: a number presented
	// without them would be a promise the scan need not keep.
	Caveats []string `json:"caveats,omitempty"`
}

// TemplateTag is one tag and how many selected templates carry it.
type TemplateTag struct {
	Tag   string `json:"tag"`
	Count int    `json:"count"`
}

// GetID identifies a preview by the profile it describes.
func (p TemplatePreview) GetID() string {
	if p.Profile == "" {
		return p.Engine
	}
	return p.Profile
}

// GetName summarises the preview.
func (p TemplatePreview) GetName() string { return p.Engine }
