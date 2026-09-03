package store

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// ConfigPins returns the catalog config item chosen for each of these
// resources. Resources nobody has chosen for are absent rather than zero, so a
// caller can tell "attach here" from "nothing has been decided".
func (s *Store) ConfigPins(ctx context.Context, resourceIDs []string) (map[string]api.ConfigPin, error) {
	pins := map[string]api.ConfigPin{}
	if len(resourceIDs) == 0 {
		return pins, nil
	}
	var rows []models.Resource
	if err := s.DB(ctx).Model(&models.Resource{}).
		Select("id", "config_id", "config_rolled_up").
		Where("id IN ? AND config_id IS NOT NULL", resourceIDs).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("read the config choices for %d resources: %w", len(resourceIDs), err)
	}
	for _, row := range rows {
		if row.ConfigID == nil {
			continue
		}
		pins[row.ID] = api.ConfigPin{ConfigID: *row.ConfigID, RolledUp: row.ConfigRolledUp}
	}
	return pins, nil
}

// SetConfigPins remembers a choice against the resources it was made for.
//
// One statement per distinct choice rather than per resource: an ambiguous
// account is the answer for everything inside it, so the interesting case is one
// config item and several hundred resources. Both the groups and the ids within
// them are ordered, because two syncs of overlapping selections take row locks
// here and an unordered update is a deadlock waiting for load.
func (s *Store) SetConfigPins(ctx context.Context, pins map[string]api.ConfigPin) error {
	grouped := map[api.ConfigPin][]string{}
	for id, pin := range pins {
		grouped[pin] = append(grouped[pin], id)
	}
	choices := make([]api.ConfigPin, 0, len(grouped))
	for pin := range grouped {
		choices = append(choices, pin)
	}
	sort.Slice(choices, func(i, j int) bool { return choices[i].ConfigID < choices[j].ConfigID })

	for _, pin := range choices {
		ids := grouped[pin]
		sort.Strings(ids)
		err := s.DB(ctx).Model(&models.Resource{}).Where("id IN ?", ids).Updates(map[string]any{
			"config_id":        pin.ConfigID,
			"config_rolled_up": pin.RolledUp,
			"updated_at":       gorm.Expr("now()"),
		}).Error
		if err != nil {
			return fmt.Errorf("remember config item %s for %d resources: %w", pin.ConfigID, len(ids), err)
		}
	}
	return nil
}

// ClearConfigPin removes the catalog choice from one resource and returns the
// item that was unlinked. The row lock makes the returned id and cleared value
// one decision when a sync is updating the same resource concurrently.
func (s *Store) ClearConfigPin(ctx context.Context, resourceID string) (string, error) {
	var removed string
	err := s.DB(ctx).Transaction(func(tx *gorm.DB) error {
		var resource models.Resource
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Select("id", "config_id").First(&resource, "id = ?", resourceID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return NotFound("resource", resourceID)
			}
			return fmt.Errorf("read resource %s config link: %w", resourceID, err)
		}
		if resource.ConfigID == nil {
			return fmt.Errorf("resource %s has no config link", resourceID)
		}
		removed = *resource.ConfigID
		if err := tx.Model(&models.Resource{}).Where("id = ?", resourceID).Updates(map[string]any{
			"config_id":        nil,
			"config_rolled_up": false,
			"updated_at":       gorm.Expr("now()"),
		}).Error; err != nil {
			return fmt.Errorf("remove config link %s from resource %s: %w", removed, resourceID, err)
		}
		return nil
	})
	return removed, err
}
