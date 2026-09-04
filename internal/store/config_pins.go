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

// ConfigPins returns the persisted catalog link for each resource. Rows without
// a link are absent; legacy links without a method are manual because only a
// person could populate config_id before automatic links were introduced.
func (s *Store) ConfigPins(ctx context.Context, resourceIDs []string) (map[string]api.ConfigPin, error) {
	pins := map[string]api.ConfigPin{}
	if len(resourceIDs) == 0 {
		return pins, nil
	}
	var rows []models.Resource
	if err := s.DB(ctx).Model(&models.Resource{}).
		Select("id", "config_id", "config_match_method", "config_rolled_up", "config_server").
		Where("id IN ? AND config_id IS NOT NULL", resourceIDs).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("read the config links for %d resources: %w", len(resourceIDs), err)
	}
	for _, row := range rows {
		if row.ConfigID == nil {
			continue
		}
		method := api.ConfigMatchMethod(row.ConfigMatchMethod)
		if method == "" {
			method = api.ConfigMatchManual
		}
		pins[row.ID] = api.ConfigPin{
			ConfigID: *row.ConfigID, Method: method,
			RolledUp: row.ConfigRolledUp, Server: row.ConfigServer,
		}
	}
	return pins, nil
}

// SetConfigPins records the config links a successful sync used.
//
// One statement per distinct link rather than per resource: an account roll-up
// can be the answer for several hundred resources. Both groups and ids are
// ordered because concurrent syncs of overlapping selections take row locks.
func (s *Store) SetConfigPins(ctx context.Context, pins map[string]api.ConfigPin) error {
	grouped := map[api.ConfigPin][]string{}
	for id, pin := range pins {
		if pin.Method == "" {
			pin.Method = api.ConfigMatchManual
		}
		grouped[pin] = append(grouped[pin], id)
	}
	choices := make([]api.ConfigPin, 0, len(grouped))
	for pin := range grouped {
		choices = append(choices, pin)
	}
	sort.Slice(choices, func(i, j int) bool {
		if choices[i].Server != choices[j].Server {
			return choices[i].Server < choices[j].Server
		}
		if choices[i].ConfigID != choices[j].ConfigID {
			return choices[i].ConfigID < choices[j].ConfigID
		}
		return choices[i].Method < choices[j].Method
	})

	for _, pin := range choices {
		ids := grouped[pin]
		sort.Strings(ids)
		err := s.DB(ctx).Model(&models.Resource{}).Where("id IN ?", ids).Updates(map[string]any{
			"config_id":           pin.ConfigID,
			"config_match_method": pin.Method,
			"config_rolled_up":    pin.RolledUp,
			"config_server":       pin.Server,
			"updated_at":          gorm.Expr("now()"),
		}).Error
		if err != nil {
			return fmt.Errorf("store config link %s for %d resources: %w", pin.ConfigID, len(ids), err)
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
			"config_id":           nil,
			"config_match_method": api.ConfigMatchManual,
			"config_rolled_up":    false,
			"config_server":       "",
			"updated_at":          gorm.Expr("now()"),
		}).Error; err != nil {
			return fmt.Errorf("remove config link %s from resource %s: %w", removed, resourceID, err)
		}
		return nil
	})
	return removed, err
}
