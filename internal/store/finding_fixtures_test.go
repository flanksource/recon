package store_test

import (
	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/ocsf"
)

// detection is the OCSF half of a finding, filled the way every adapter fills
// it: the attributes the schema requires of every Detection Finding, and the
// title in finding_info where it now lives rather than in a column beside it.
//
// Shared across the store specs because the identity and severity are what they
// are about, and repeating the six required scalars in each literal buries that
// under boilerplate that is the same every time.
func detection(checkID, title string, severity api.Severity) ocsf.DetectionFinding {
	if title == "" {
		title = checkID
	}
	return ocsf.DetectionFinding{
		ClassUID:    ocsf.ClassUID,
		CategoryUID: ocsf.CategoryUID,
		ActivityID:  ocsf.ActivityIDCreate,
		TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
		SeverityID:  api.SeverityID(severity),
		FindingInfo: &ocsf.FindingInfo{UID: checkID, Title: title},
	}
}
