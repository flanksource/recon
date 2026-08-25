package api

import "github.com/flanksource/recon/internal/ocsf"

// Recon's ladder and OCSF's scale, which are the same ladder with different
// names for two of its rungs.
//
// OCSF calls the bottom rung Informational and reserves 0 for Unknown, so the
// two vocabularies line up rung for rung apart from Fatal — which OCSF defines
// as "an error occurred but it is too late to take remedial action" and which no
// scan engine recon runs reports. It maps to Critical on the way in rather than
// to Unknown: a finding an engine considered the most severe thing it found must
// not be filed under "nobody could classify this".
var severityScale = map[Severity]ocsf.SeverityID{
	SeverityCritical: ocsf.SeverityIDCritical,
	SeverityHigh:     ocsf.SeverityIDHigh,
	SeverityMedium:   ocsf.SeverityIDMedium,
	SeverityLow:      ocsf.SeverityIDLow,
	SeverityInfo:     ocsf.SeverityIDInformational,
	SeverityUnknown:  ocsf.SeverityIDUnknown,
}

// SeverityID renders recon's severity on OCSF's scale.
func SeverityID(severity Severity) ocsf.SeverityID {
	if id, known := severityScale[severity]; known {
		return id
	}
	return ocsf.SeverityIDUnknown
}

// SeverityOf reads OCSF's scale back into recon's vocabulary, which is what the
// UI groups, sorts and filters by.
func SeverityOf(id ocsf.SeverityID) Severity {
	switch id {
	case ocsf.SeverityIDCritical, ocsf.SeverityIDFatal:
		return SeverityCritical
	case ocsf.SeverityIDHigh:
		return SeverityHigh
	case ocsf.SeverityIDMedium:
		return SeverityMedium
	case ocsf.SeverityIDLow:
		return SeverityLow
	case ocsf.SeverityIDInformational:
		return SeverityInfo
	default:
		return SeverityUnknown
	}
}

// SeverityLevel reports the finding's severity in recon's vocabulary.
//
// A method rather than a field, because the embedded OCSF record already
// carries severity_id and a second field holding the same fact is a second
// thing to keep in step. Named so it does not shadow OCSF's own `severity`,
// which stays what the schema says it is — the caption of severity_id — and
// would otherwise be unreachable behind a promoted method of the same name.
func (f Finding) SeverityLevel() Severity { return SeverityOf(f.SeverityID) }
