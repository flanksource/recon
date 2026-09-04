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

func InsightAnalysisID(configID uuid.UUID, resource api.Resource, engine, checkID string) uuid.UUID {
	return uuid.NewSHA1(reconNamespace, []byte(strings.Join([]string{
		configID.String(), resource.Provider, resource.Scope, resource.UID, engine, checkID,
	}, "|")))
}

func StateAnalysis(state api.InsightState, configID uuid.UUID) (dutymodels.ConfigAnalysis, error) {
	analysisType, err := analysisTypeOf(state.State.Engine)
	if err != nil {
		return dutymodels.ConfigAnalysis{}, err
	}
	status, err := analysisStatus(state.State.Status)
	if err != nil {
		return dutymodels.ConfigAnalysis{}, err
	}
	first, err := stateTimestamp(state.State.FirstSeen)
	if err != nil {
		return dutymodels.ConfigAnalysis{}, fmt.Errorf("finding state %s first seen: %w", state.State.ID, err)
	}
	last, err := stateTimestamp(state.State.LastSeen)
	if err != nil {
		return dutymodels.ConfigAnalysis{}, fmt.Errorf("finding state %s last seen: %w", state.State.ID, err)
	}
	summary := state.Finding.GetName()
	if summary == "" {
		summary = state.State.CheckID
	}
	return dutymodels.ConfigAnalysis{
		ID:       InsightAnalysisID(configID, state.Resource, state.State.Engine, state.State.CheckID),
		ConfigID: configID, Analyzer: state.State.CheckID, Summary: summary,
		Message: message(state.Finding), Status: status,
		Severity: severityOf(api.Severity(state.State.Severity)), AnalysisType: analysisType,
		Analysis: stateAnalysisBody(state), Source: "recon/" + state.State.Engine,
		FirstObserved: &first, LastObserved: &last,
	}, nil
}

// ClosedStateAnalysis resolves the deterministic insight on its previous config
// item before a resource link moves or disappears.
func ClosedStateAnalysis(state api.InsightState, configID uuid.UUID, reason string) (dutymodels.ConfigAnalysis, error) {
	analysis, err := StateAnalysis(state, configID)
	if err != nil {
		return dutymodels.ConfigAnalysis{}, err
	}
	analysis.Status = dutymodels.AnalysisStatusResolved
	analysis.Analysis["finding_status"] = api.StatusResolved
	analysis.Analysis["resolution_reason"] = reason
	return analysis, nil
}

func analysisStatus(status string) (string, error) {
	switch status {
	case api.StatusOpen, api.StatusManual:
		return dutymodels.AnalysisStatusOpen, nil
	case api.StatusResolved:
		return dutymodels.AnalysisStatusResolved, nil
	case api.StatusMuted:
		return dutymodels.AnalysisStatusSilenced, nil
	default:
		return "", fmt.Errorf("unknown finding state status %q", status)
	}
}

func stateTimestamp(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q", value)
}

func stateAnalysisBody(state api.InsightState) dutytypes.JSONMap {
	body := analysisBody(state.Scan, state.Finding)
	body["finding_state_id"] = state.State.ID
	body["finding_status"] = state.State.Status
	body["resource"] = dutytypes.JSONMap{
		"provider": state.Resource.Provider, "scope": state.Resource.Scope,
		"uid": state.Resource.UID, "name": state.Resource.Name, "type": state.Resource.Type,
	}
	if state.State.Reason != "" {
		body["reason"] = state.State.Reason
	}
	return body
}
