package store

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/ocsf"
)

// Filling in what a page of ledger rows points at.
//
// Three keyed lookups, one per page: the resources, the evidence rows the states
// name, and the catalogue entries for the checks they are about.
//
// It used to re-derive the evidence instead — every finding ever recorded
// against every resource on the page, DISTINCT ON'd down to the newest per
// (resource, engine, check). That read the whole of a resource's history to
// render one screen of it, selected `raw`, `request` and `response` while doing
// so, and answered a question nobody asked: finding_states.finding_id already
// records which finding is the evidence, and a resolved state deliberately
// carries none. The newest-finding rule meant a resolved state was rendered with
// the last time it failed, presented as its finding.
func (s *Store) hydrateFindingStates(ctx context.Context, rows []models.FindingState) ([]api.FindingState, error) {
	if len(rows) == 0 {
		return []api.FindingState{}, nil
	}

	resources, err := s.hydrateResources(ctx, rows)
	if err != nil {
		return nil, err
	}
	evidence, err := s.hydrateEvidence(ctx, rows)
	if err != nil {
		return nil, err
	}
	catalogue, err := s.hydrateCatalogue(ctx, rows)
	if err != nil {
		return nil, err
	}

	states := make([]api.FindingState, 0, len(rows))
	for _, row := range rows {
		state := row.Document()
		resource, found := resources[row.ResourceID]
		if !found {
			return nil, fmt.Errorf("finding state %s references missing resource %s", row.ID, row.ResourceID)
		}
		state.Resource = &resource

		finding := evidenceFor(row, evidence, catalogue)
		finding.Resources = []api.ResourceRef{resource.Ref()}
		state.Finding = &finding
		states = append(states, state)
	}
	return states, nil
}

// evidenceFor prefers the finding the state names, falls back to what the check
// is, and finally to the little the state itself knows.
//
// The last case is a check the catalogue has not caught up with — there is no
// foreign key precisely so that cannot block the ledger — and it is marked
// synthetic like any other description that is not evidence.
func evidenceFor(
	row models.FindingState,
	evidence map[string]api.Finding,
	catalogue map[string]api.Finding,
) api.Finding {
	if row.FindingID != nil {
		if finding, found := evidence[*row.FindingID]; found {
			return finding
		}
	}
	if finding, found := catalogue[checkKey(row.Engine, row.CheckID)]; found {
		// The verdict's severity, not the check's: finding_states keeps the one
		// the last failing run reported, and that is what the row is about.
		finding.SeverityID = api.SeverityID(api.Severity(row.Severity))
		return finding
	}
	// Nothing is left that describes this check — no evidence, and no catalogue
	// entry either. The check id is all there is to render it by.
	return api.Finding{
		DetectionFinding: ocsf.DetectionFinding{
			ClassUID:    ocsf.ClassUID,
			CategoryUID: ocsf.CategoryUID,
			ActivityID:  ocsf.ActivityIDCreate,
			TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
			SeverityID:  api.SeverityID(api.Severity(row.Severity)),
			FindingInfo: &ocsf.FindingInfo{UID: row.CheckID, Title: row.CheckID},
			Metadata: &ocsf.Metadata{
				Version:   ocsf.Version,
				EventCode: row.CheckID,
				Product:   &ocsf.Product{Name: row.Engine, VendorName: api.Vendor},
			},
		},
		CheckID:   row.CheckID,
		Engine:    row.Engine,
		Synthetic: true,
	}
}

func (s *Store) hydrateResources(ctx context.Context, rows []models.FindingState) (map[string]api.Resource, error) {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ResourceID)
	}
	var found []models.Resource
	if err := s.DB(ctx).Where("id = ANY(?)", pq.StringArray(ids)).Find(&found).Error; err != nil {
		return nil, fmt.Errorf("hydrate finding state resources: %w", err)
	}
	// The counts are read rather than passed as zero. api.Resource.Findings means
	// "what is open against this", and ListResources fills it in honestly — so a
	// nested copy hard-coded to 0 was the same field carrying two meanings with
	// nothing in the response to say which.
	open, err := s.openCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	resources := make(map[string]api.Resource, len(found))
	for _, row := range found {
		counted := open[row.ID]
		resources[row.ID] = row.Document(counted.total, counted.severities)
	}
	return resources, nil
}

type openCount struct {
	total      int
	severities map[string]int
}

// openCounts is the lateral in resourceQuery, asked for a known set of ids.
func (s *Store) openCounts(ctx context.Context, ids []string) (map[string]openCount, error) {
	var rows []struct {
		ResourceID string `gorm:"column:resource_id"`
		Severity   string `gorm:"column:severity"`
		N          int    `gorm:"column:n"`
	}
	if err := s.DB(ctx).Raw(`
		SELECT resource_id, severity, COUNT(*) AS n
		FROM finding_states
		WHERE resource_id = ANY(?) AND `+stateIsOpen+`
		GROUP BY resource_id, severity`, pq.StringArray(ids)).Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("count open findings for %d resources: %w", len(ids), err)
	}
	counts := make(map[string]openCount, len(rows))
	for _, row := range rows {
		counted := counts[row.ResourceID]
		if counted.severities == nil {
			counted.severities = map[string]int{}
		}
		counted.total += row.N
		counted.severities[row.Severity] = row.N
		counts[row.ResourceID] = counted
	}
	return counts, nil
}

// hydrateEvidence reads exactly the findings the states name, and nothing else.
func (s *Store) hydrateEvidence(ctx context.Context, rows []models.FindingState) (map[string]api.Finding, error) {
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.FindingID != nil {
			ids = append(ids, *row.FindingID)
		}
	}
	if len(ids) == 0 {
		return map[string]api.Finding{}, nil
	}
	var found []models.Finding
	if err := s.DB(ctx).Where("id = ANY(?)", pq.StringArray(ids)).Find(&found).Error; err != nil {
		return nil, fmt.Errorf("hydrate finding state evidence: %w", err)
	}
	documents, err := s.documents(ctx, found)
	if err != nil {
		return nil, err
	}
	evidence := make(map[string]api.Finding, len(documents))
	for _, document := range documents {
		evidence[document.ID] = document
	}
	return evidence, nil
}

func (s *Store) hydrateCatalogue(ctx context.Context, rows []models.FindingState) (map[string]api.Finding, error) {
	engines := make([]string, 0, len(rows))
	checks := make([]string, 0, len(rows))
	seen := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		key := checkKey(row.Engine, row.CheckID)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		engines = append(engines, row.Engine)
		checks = append(checks, row.CheckID)
	}
	var found []models.Check
	if err := s.DB(ctx).Raw(catalogueSQL, map[string]any{
		"engines": stringArray(engines), "checks": stringArray(checks),
	}).Scan(&found).Error; err != nil {
		return nil, fmt.Errorf("hydrate finding state checks: %w", err)
	}
	catalogue := make(map[string]api.Finding, len(found))
	for _, row := range found {
		catalogue[checkKey(row.Engine, row.CheckID)] = row.Finding()
	}
	return catalogue, nil
}

func checkKey(engine, checkID string) string { return engine + "\x00" + checkID }
