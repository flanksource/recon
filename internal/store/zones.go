package store

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// ZoneOpts selects zones. It carries no filters: the list is short by nature —
// these are the domains an organisation owns.
type ZoneOpts struct{}

// ListZoneDocuments returns the configured zones as entity records.
func (s *Store) ListZoneDocuments(ctx context.Context, _ ZoneOpts) ([]api.Zone, error) {
	names, err := s.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	zones := make([]api.Zone, 0, len(names))
	for _, name := range names {
		zones = append(zones, api.Zone{Zone: name})
	}
	return zones, nil
}

// GetZone returns one configured zone.
func (s *Store) GetZone(ctx context.Context, name string) (api.Zone, error) {
	var row models.Zone
	err := s.DB(ctx).Where("zone = ?", normaliseZone(name)).First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return api.Zone{}, NotFound("zone", name)
		}
		return api.Zone{}, fmt.Errorf("get zone %s: %w", name, err)
	}
	return api.Zone{Zone: row.Zone}, nil
}

// AddZone configures a zone to enumerate.
//
// Zones are what seed discovery: subfinder enumerates them, DNS is asked for
// their NS and MX targets, and the static scrape uses them to decide what is in
// scope. With none configured, discovery has nothing to start from.
func (s *Store) AddZone(ctx context.Context, name string) (api.Zone, error) {
	zone := normaliseZone(name)
	if err := validZone(zone); err != nil {
		return api.Zone{}, err
	}

	err := s.DB(ctx).Clauses(clause.OnConflict{DoNothing: true}).
		Create(&models.Zone{Zone: zone}).Error
	if err != nil {
		return api.Zone{}, fmt.Errorf("add zone %s: %w", zone, err)
	}
	return api.Zone{Zone: zone}, nil
}

// DeleteZone stops enumerating a zone. Targets already discovered under it are
// left alone: they are still real hosts, and removing them would quietly shrink
// the inventory.
func (s *Store) DeleteZone(ctx context.Context, name string) error {
	result := s.DB(ctx).Where("zone = ?", normaliseZone(name)).Delete(&models.Zone{})
	if result.Error != nil {
		return fmt.Errorf("delete zone %s: %w", name, result.Error)
	}
	if result.RowsAffected == 0 {
		return NotFound("zone", name)
	}
	return nil
}

func normaliseZone(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func validZone(zone string) error {
	if zone == "" {
		return fmt.Errorf("zone is required")
	}
	if !strings.Contains(zone, ".") {
		return fmt.Errorf("zone %q is not a domain name", zone)
	}
	if strings.ContainsAny(zone, "*/ :") {
		return fmt.Errorf("zone %q contains characters a domain name cannot", zone)
	}
	return nil
}
