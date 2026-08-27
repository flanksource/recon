package store

import (
	"context"
	"fmt"
	"sort"

	"gorm.io/gorm"

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
