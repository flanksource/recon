package store

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"gorm.io/gorm"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

func validateProviderContext(
	ctx context.Context,
	validator ProviderContextValidator,
	target api.TargetDocument,
) error {
	if target.Kind != api.KindProviderContext || validator == nil {
		return nil
	}
	if err := validator(ctx, target); err != nil {
		return fmt.Errorf("provider context %s: %w", target.ID, err)
	}
	return nil
}

// validateProfiles refuses a target that opts into a profile nobody defined.
// A name is provider-qualified through its engine identity so two engines may
// expose the same friendly profile name without either target becoming
// ambiguous.
func validateProfiles(db *gorm.DB, targetID string, profiles []string) error {
	if len(profiles) == 0 {
		return nil
	}

	var rows []models.EngineProfile
	if err := db.Model(&models.EngineProfile{}).
		Where("kind = ?", api.KindScan).
		Select("kind", "engine", "name").Find(&rows).Error; err != nil {
		return fmt.Errorf("read scan profiles: %w", err)
	}

	known := make([]string, 0, len(rows))
	available := make(map[string]bool, len(rows))
	for _, row := range rows {
		id := strings.Join([]string{row.Kind, row.Engine, row.Name}, ":")
		known = append(known, id)
		available[id] = true
	}

	var unknown []string
	for _, profile := range profiles {
		kind, _, _, err := splitProfileID(profile)
		if err != nil || kind != string(api.KindScan) || !available[profile] {
			unknown = append(unknown, profile)
		}
	}
	if len(unknown) == 0 {
		return nil
	}

	sort.Strings(known)
	return fmt.Errorf("%s: unknown scan profile %s (value must be one of: %s)",
		targetID, strings.Join(unknown, ", "), strings.Join(known, ", "))
}
