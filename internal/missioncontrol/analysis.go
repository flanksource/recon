package missioncontrol

import (
	"fmt"
	"strings"
	"time"

	dutymodels "github.com/flanksource/duty/models"
	dutytypes "github.com/flanksource/duty/types"
	"github.com/google/uuid"

	"github.com/flanksource/recon/internal/api"
)

// reconNamespace seeds every identifier this package derives. A fixed namespace
// is what makes an insight's id a function of what it says rather than of when
// it was uploaded, so re-uploading the same finding updates one row instead of
// accumulating a new one per scan.
var reconNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/flanksource/recon"))

// statusOpen is the only status recon writes. Resolving an insight is a
// judgement about the finding having gone away, which needs a comparison
// against a later scan — not something a single upload can assert.
const statusOpen = "open"

// AnalysisID is the insight's identity: the config it is about, what found it,
// and where. Two scans that see the same problem in the same place produce the
// same id, which is what makes an upload idempotent — Mission Control upserts
// on the primary key, and first_observed is create-only, so the original
// sighting survives.
func AnalysisID(configID uuid.UUID, finding api.Finding) uuid.UUID {
	return uuid.NewSHA1(reconNamespace, []byte(strings.Join([]string{
		configID.String(), finding.TemplateID, finding.MatchedAt,
	}, "|")))
}

// Analysis projects one finding onto the insight Mission Control stores.
//
// The typed columns are what the catalog filters and sorts on; the engine's own
// record goes into Analysis whole, because a finding is evidence and the detail
// that did not fit the schema is exactly what someone investigating needs.
func Analysis(scan api.Scan, finding api.Finding, configID uuid.UUID) (dutymodels.ConfigAnalysis, error) {
	analysisType, err := analysisTypeOf(scan.Engine)
	if err != nil {
		return dutymodels.ConfigAnalysis{}, err
	}

	observed := observedAt(scan, finding)
	return dutymodels.ConfigAnalysis{
		ID:            AnalysisID(configID, finding),
		ConfigID:      configID,
		Analyzer:      finding.TemplateID,
		Summary:       finding.Name,
		Message:       message(finding),
		Status:        statusOpen,
		Severity:      severityOf(finding.Severity),
		AnalysisType:  analysisType,
		Analysis:      analysisBody(scan, finding),
		Source:        "recon/" + scan.Engine,
		FirstObserved: &observed,
		LastObserved:  &observed,
	}, nil
}

// message is what the insight reads as. Remediation and references are the part
// a reader acts on, so they are in the body rather than buried in the raw
// record.
func message(finding api.Finding) string {
	sections := []string{finding.Name}
	if finding.MatchedAt != "" {
		sections = append(sections, "Matched at: "+finding.MatchedAt)
	}
	if finding.Remediation != "" {
		sections = append(sections, "Remediation: "+finding.Remediation)
	}
	if len(finding.Reference) > 0 {
		sections = append(sections, "References:\n"+strings.Join(finding.Reference, "\n"))
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
		"recon_severity": string(finding.Severity),
	}
	if finding.TargetID != "" {
		body["target_id"] = finding.TargetID
	}
	if len(finding.Tags) > 0 {
		body["tags"] = finding.Tags
	}
	if len(finding.Extracted) > 0 {
		body["extracted"] = finding.Extracted
	}
	if finding.MatcherName != "" {
		body["matcher"] = finding.MatcherName
	}
	if finding.ScanID != "" && finding.LineNo > 0 {
		body["finding_id"] = fmt.Sprintf("%s#%d", finding.ScanID, finding.LineNo)
	}
	if len(finding.Raw) > 0 {
		body["raw"] = finding.Raw
	}
	return body
}

// observedAt prefers the engine's own timestamp for the finding and falls back
// to the run's clock. api.Scan renders its timestamps as local wall clock with
// no offset — see models.Scan.Document — so they are parsed back the same way.
func observedAt(scan api.Scan, finding api.Finding) time.Time {
	if finding.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, finding.Timestamp); err == nil {
			return parsed
		}
	}
	for _, stamp := range []string{scan.FinishedAt, scan.StartedAt} {
		if parsed, err := time.ParseInLocation("2006-01-02T15:04:05", stamp, time.Local); err == nil {
			return parsed
		}
	}
	return time.Now()
}
