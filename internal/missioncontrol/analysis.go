package missioncontrol

import (
	"fmt"
	"strings"

	dutytypes "github.com/flanksource/duty/types"
	"github.com/google/uuid"

	"github.com/flanksource/recon/internal/api"
)

// reconNamespace seeds every identifier this package derives. A fixed namespace
// is what makes an insight's id a function of what it says rather than of when
// it was uploaded, so re-uploading the same finding updates one row instead of
// accumulating a new one per scan.
var reconNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/flanksource/recon"))

// message is what the insight reads as. Remediation and references are the part
// a reader acts on, so they are in the body rather than buried in the raw
// record.
func message(finding api.Finding) string {
	sections := []string{finding.GetName()}
	if finding.FindingInfo != nil && finding.FindingInfo.Desc != "" {
		sections = append(sections, finding.FindingInfo.Desc)
	}
	if finding.MatchedAt != "" {
		sections = append(sections, "Matched at: "+finding.MatchedAt)
	}
	if finding.Remediation != nil {
		if finding.Remediation.Desc != "" {
			sections = append(sections, "Remediation: "+finding.Remediation.Desc)
		}
		if len(finding.Remediation.References) > 0 {
			sections = append(sections, "References:\n"+strings.Join(finding.Remediation.References, "\n"))
		}
	}
	return strings.Join(sections, "\n\n")
}

// analysisBody carries the engine's own record plus the run that produced it.
// The scan fields are what turns "this host has a weak cipher" back into a
// reproducible command, and recon_severity records the rung the engine actually
// reported when it does not exist upstream.
func analysisBody(scan api.Scan, finding api.Finding) dutytypes.JSONMap {
	body := dutytypes.JSONMap{
		"scan_id":        scan.ID,
		"engine":         scan.Engine,
		"profile":        scan.Profile,
		"host":           finding.Host,
		"matched_at":     finding.MatchedAt,
		"recon_severity": string(finding.SeverityLevel()),
		// The OCSF identity, so a consumer that speaks the schema can read the
		// insight without knowing anything about recon.
		"class_uid":   finding.ClassUID,
		"severity_id": int(finding.SeverityID),
		"check_id":    finding.CheckID,
	}
	if finding.TargetID != "" {
		body["target_id"] = finding.TargetID
	}
	if len(finding.Tags) > 0 {
		body["tags"] = finding.Tags
	}
	if finding.ScanID != "" && finding.LineNo > 0 {
		body["finding_id"] = fmt.Sprintf("%s#%d", finding.ScanID, finding.LineNo)
	}
	// The engine's own record used to go here whole and unbounded — every
	// insight carried a full copy, and one provider document runs to 95KB. What
	// a reader needs is modelled now, and what is not modelled is bounded.
	if len(finding.Evidences) > 0 {
		body["evidences"] = finding.Evidences
	}
	if len(finding.Unmapped) > 0 {
		body["unmapped"] = finding.Unmapped
	}
	return body
}
