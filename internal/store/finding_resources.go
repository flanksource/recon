package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// findingResources loads the subjects a page of findings names.
//
// One keyed lookup for the whole page rather than a query per finding, matching
// how hydrateFindingStates fills in what a page of ledger rows points at. A
// query per row is what made the finding list slow enough to need fixing once
// already.
//
// The join is the point of the relation. A resource's key is (provider, scope,
// uid) and OCSF carries only the uid on each entry of its resources array, so
// the identity has to come from the resources table — which holds all three —
// rather than from the stored record.
func (s *Store) findingResources(ctx context.Context, ids []string) (map[string][]api.ResourceRef, error) {
	if len(ids) == 0 {
		return map[string][]api.ResourceRef{}, nil
	}

	var rows []struct {
		FindingID string
		ID        string
		Provider  string
		Scope     string
		UID       string
		Name      string
		Type      string
		Service   string
		Region    string
	}
	err := s.DB(ctx).
		Table("finding_resources").
		Select(`finding_resources.finding_id AS finding_id,
			resources.id AS id,
			resources.provider AS provider,
			resources.scope AS scope,
			resources.uid AS uid,
			resources.name AS name,
			resources.type AS type,
			resources.service AS service,
			resources.region AS region`).
		Joins("JOIN resources ON resources.id = finding_resources.resource_id").
		Where("finding_resources.finding_id IN ?", ids).
		// The record's own order, which decides which subject is canonical.
		Order("finding_resources.finding_id, finding_resources.ordinal").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("load finding resources: %w", err)
	}

	found := make(map[string][]api.ResourceRef, len(ids))
	for _, row := range rows {
		found[row.FindingID] = append(found[row.FindingID], api.ResourceRef{
			ID:       row.ID,
			Provider: row.Provider,
			Scope:    row.Scope,
			UID:      row.UID,
			Name:     row.Name,
			Type:     row.Type,
			Service:  row.Service,
			Region:   row.Region,
		})
	}
	return found, nil
}

// documents renders a page of findings with the subjects they name.
func (s *Store) documents(ctx context.Context, rows []models.Finding) ([]api.Finding, error) {
	if len(rows) == 0 {
		return []api.Finding{}, nil
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	resources, err := s.findingResources(ctx, ids)
	if err != nil {
		return nil, err
	}

	documents := make([]api.Finding, 0, len(rows))
	for _, row := range rows {
		documents = append(documents, row.Document(resources[row.ID]))
	}
	return documents, nil
}

// saveFindingResources records every subject each finding named.
//
// Written for all of them, not only the canonical one findings.resource_id
// points at: a check that fails against forty buckets names forty, and the
// other thirty-nine have nowhere else to live once the raw record is gone.
func saveFindingResources(db *gorm.DB, rows []models.FindingResource) error {
	if len(rows) == 0 {
		return nil
	}
	if err := db.CreateInBatches(rows, 500).Error; err != nil {
		return fmt.Errorf("save finding resources: %w", err)
	}
	return nil
}
