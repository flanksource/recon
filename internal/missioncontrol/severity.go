// Package missioncontrol uploads recon findings into Mission Control, where
// they appear as insights (config_analysis) attached to the config item the
// finding is actually about.
//
// The client is the one faro already authenticated: `faro auth login` is the
// whole setup, and no server URL or token is configured here.
package missioncontrol

import (
	"fmt"

	dutymodels "github.com/flanksource/duty/models"

	"github.com/flanksource/recon/internal/api"
)

// severities maps recon's ladder onto duty's.
//
// The two agree on every rung except recon's `unknown`, which exists because an
// engine may report a vocabulary nobody recognises and a finding nobody can
// classify is still a finding. Mission Control has no such rung, so it lands on
// `info` — the only choice that neither invents a severity nor drops the
// finding. What the engine actually said is kept in the analysis body, so the
// downgrade is recorded rather than silent.
var severities = map[api.Severity]dutymodels.Severity{
	api.SeverityCritical: dutymodels.SeverityCritical,
	api.SeverityHigh:     dutymodels.SeverityHigh,
	api.SeverityMedium:   dutymodels.SeverityMedium,
	api.SeverityLow:      dutymodels.SeverityLow,
	api.SeverityInfo:     dutymodels.SeverityInfo,
	api.SeverityUnknown:  dutymodels.SeverityInfo,
}

func severityOf(severity api.Severity) dutymodels.Severity {
	if mapped, ok := severities[severity]; ok {
		return mapped
	}
	// ParseSeverity already folds anything unrecognised into SeverityUnknown, so
	// reaching here means a rung was added to api.Severity and not to this table.
	return dutymodels.SeverityInfo
}

// analysisTypes says what kind of question each engine answers. Nuclei and
// trivy probe for weaknesses; prowler and inspec check an account against a
// benchmark. Mission Control filters insights on this, so getting it wrong puts
// a CIS failure in with the CVEs.
var analysisTypes = map[string]dutymodels.AnalysisType{
	"nuclei":  dutymodels.AnalysisTypeSecurity,
	"trivy":   dutymodels.AnalysisTypeSecurity,
	"prowler": dutymodels.AnalysisTypeCompliance,
	"inspec":  dutymodels.AnalysisTypeCompliance,
}

// analysisTypeOf fails rather than defaulting: a new engine that silently
// reported everything as `security` would misfile every one of its findings,
// and the miss is invisible once the rows are upstream.
func analysisTypeOf(engine string) (dutymodels.AnalysisType, error) {
	if analysisType, ok := analysisTypes[engine]; ok {
		return analysisType, nil
	}
	return "", fmt.Errorf("engine %q has no Mission Control analysis type; add it to analysisTypes", engine)
}
