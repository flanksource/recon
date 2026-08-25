package api

import (
	"strings"

	"github.com/flanksource/recon/internal/ocsf"
)

// Severity is the normalised severity ladder. Engines report their own
// vocabularies; anything unrecognised becomes SeverityUnknown rather than being
// dropped, because a finding nobody can classify is still a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityUnknown  Severity = "unknown"
)

// Severities lists the ladder from most to least severe — the order the UI
// groups and sorts by.
func Severities() []Severity {
	return []Severity{
		SeverityCritical, SeverityHigh, SeverityMedium,
		SeverityLow, SeverityInfo, SeverityUnknown,
	}
}

// ParseSeverity normalises an engine's severity string.
func ParseSeverity(value string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(value))) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityMedium:
		return SeverityMedium
	case SeverityLow:
		return SeverityLow
	case SeverityInfo:
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// What kind of verdict a finding records. Deliberately recon's own vocabulary:
// an engine's own status codes mean whatever that engine means by them, and the
// lifecycle needs one answer it can key on across all of them.
const (
	VerdictFail   = "fail"
	VerdictManual = "manual"
)

// Vendor is who OCSF considers the producer of a record, which it asks for
// separately from the product. Every finding recon stores was produced by recon
// running some engine, so the vendor is constant and the engine is the product.
const Vendor = "flanksource-recon"

// ProfileCloud is the OCSF profile a record that audits a cloud account
// declares. Declaring it is what makes cloud.provider required of that record;
// an engine that scans a URL or a filesystem declares nothing and is held to
// nothing. See ocsf.Validate.
const ProfileCloud = "cloud"

// Finding is one result an engine reported, stored as an OCSF Detection
// Finding with the identity recon needs in order to track it over time.
//
// The OCSF record is embedded rather than nested, so the wire format is OCSF at
// the top level. An expression addressing finding.finding_info.title or
// finding.resources[0].uid is addressing the published schema rather than a
// recon invention, and that is what mute rules are written against.
//
// The engine's verbatim record is deliberately not here. It used to be, under
// `raw`, unbounded and shipped whole to Mission Control and into every report;
// what triage actually needs is now modelled — description and impact in
// finding_info, classification in vulnerabilities, the HTTP exchange in
// evidences — and the rest lives in the run's artifact.
type Finding struct {
	ocsf.DetectionFinding

	// ID is the persisted finding row's stable database identity.
	ID string `json:"id,omitempty"`

	// ScanID and LineNo preserve the run and source-order provenance.
	ScanID string `json:"scanId,omitempty"`
	LineNo int    `json:"lineNo,omitempty"`

	// TargetID links the provider-reported account or resource back to the
	// inventory context selected for the run. Host remains the provider's own
	// identity from the finding evidence.
	TargetID string `json:"targetId,omitempty"`

	// Engine is which scanner produced this. OCSF records it as well, in
	// metadata.product.name; this is the column recon filters and joins on.
	Engine string `json:"engine,omitempty"`

	// CheckID is the check this is an instance of — half of a finding's
	// identity, the other half being the resource. OCSF records it twice, in
	// finding_info.uid and metadata.event_code; this is the indexed column, and
	// the value stored mute rules match against.
	CheckID string `json:"checkId"`

	// Verdict is what kind of verdict this evidence is, in recon's vocabulary
	// rather than the engine's: a plain failure, or one a human still owes a
	// decision on. Empty means Fail, which is what every finding was before the
	// distinction existed.
	//
	// Not OCSF's status_id, which describes where a finding is in triage —
	// new, suppressed, resolved — rather than what the check decided.
	Verdict string `json:"verdict,omitempty"`

	// Tags are recon's own cross-cutting labels, which OCSF has no equivalent
	// for. The check catalogue is built from them and the UI filters on them, so
	// they stay a column; they are also projected into finding_info.types.
	Tags []string `json:"tags"`

	// Host and MatchedAt are evidence locations rather than resources: the
	// account or hostname a check ran against, and the display string naming
	// where it matched. Both predate resources and both are still what the UI
	// groups by, so neither is derivable from the OCSF record.
	Host      string `json:"host"`
	MatchedAt string `json:"matchedAt"`

	// Resources are the subjects the evidence names, in the engine's own order.
	// Resources[0] is the primary one — the thing the check has a verdict about
	// — and the rest are context.
	//
	// This shadows the embedded OCSF resources array deliberately. A reference
	// is keyed by (provider, scope, uid) and OCSF's resource object has nowhere
	// to put the account: at 1.5.0 it sits once at the event level, in
	// cloud.account.uid. The field name and the uid stay OCSF's, so an
	// expression reading finding.resources[0].uid reads what it looks like.
	Resources []ResourceRef `json:"resources,omitempty"`

	// Synthetic marks a document describing what the check is rather than what a
	// run observed. A resolved or muted state has no evidence attached — that is
	// what resolving it means — so what is rendered comes from the check
	// catalogue, and a reader has to be able to tell the difference.
	Synthetic bool `json:"synthetic,omitempty"`
}

// FindingPage is one server-sorted slice of the findings register.
type FindingPage struct {
	Data []Finding `json:"data"`
	Page PageInfo  `json:"page"`
}
