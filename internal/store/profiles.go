package store

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	// Registering the built-in engines is a compile-time dependency of profile
	// validation: an unpopulated registry would silently accept nothing and seed
	// no defaults, which looks like an empty database rather than a wiring bug.
	_ "github.com/flanksource/recon/internal/engines/all"
	"github.com/flanksource/recon/internal/engines/discovery"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/models"
)

// ProfileOpts selects stored engine configurations.
type ProfileOpts struct {
	Kind   []string `json:"kind,omitempty" flag:"kind" help:"Only discovery or scan profiles"`
	Engine []string `json:"engine,omitempty" flag:"engine" help:"Only profiles for these engines"`
}

// ListProfiles returns the profiles a selector matches.
func (s *Store) ListProfiles(ctx context.Context, opts ProfileOpts) ([]api.Profile, error) {
	query := s.DB(ctx).Model(&models.EngineProfile{})
	if len(opts.Kind) > 0 {
		query = query.Where("kind = ANY(?)", stringArray(opts.Kind))
	}
	if len(opts.Engine) > 0 {
		query = query.Where("engine = ANY(?)", stringArray(opts.Engine))
	}

	var rows []models.EngineProfile
	if err := query.Order("kind, engine, name").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}

	profiles := make([]api.Profile, 0, len(rows))
	for _, row := range rows {
		profiles = append(profiles, row.Document())
	}
	return profiles, nil
}

// GetProfile returns one profile, addressed as kind/engine/name.
func (s *Store) GetProfile(ctx context.Context, id string) (api.Profile, error) {
	kind, engine, name, err := splitProfileID(id)
	if err != nil {
		return api.Profile{}, err
	}

	var row models.EngineProfile
	err = s.DB(ctx).Where("kind = ? AND engine = ? AND name = ?", kind, engine, name).
		First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return api.Profile{}, NotFound("profile", id)
		}
		return api.Profile{}, fmt.Errorf("get profile %s: %w", id, err)
	}
	return row.Document(), nil
}

// SaveProfile validates a profile against its engine's catalog and stores it.
//
// Validation happens here rather than at the edge so that every path into the
// database — the API, the CLI, the defaults seeded on a blank install — is held
// to the same contract. A profile an engine would reject must never be stored.
func (s *Store) SaveProfile(ctx context.Context, profile api.Profile) (api.Profile, error) {
	spec, err := specFor(profile.Kind, profile.Engine)
	if err != nil {
		return api.Profile{}, err
	}
	if profile.Name == "" {
		return api.Profile{}, fmt.Errorf("profile name is required")
	}
	if err := spec.ValidateConfig(profile.Config); err != nil {
		return api.Profile{}, fmt.Errorf("profile %s: %w", profile.ID(), err)
	}

	row := models.ProfileFrom(profile)
	err = s.DB(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "kind"}, {Name: "engine"}, {Name: "name"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"config", "comment", "paths", "updated_at",
		}),
	}).Create(&row).Error
	if err != nil {
		return api.Profile{}, fmt.Errorf("save profile %s: %w", profile.ID(), err)
	}
	return s.GetProfile(ctx, profile.ID())
}

// DeleteProfile removes a profile.
func (s *Store) DeleteProfile(ctx context.Context, id string) error {
	kind, engine, name, err := splitProfileID(id)
	if err != nil {
		return err
	}

	result := s.DB(ctx).Where("kind = ? AND engine = ? AND name = ?", kind, engine, name).
		Delete(&models.EngineProfile{})
	if result.Error != nil {
		return fmt.Errorf("delete profile %s: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return NotFound("profile", id)
	}
	return nil
}

// SeedDefaultProfiles stores each engine's built-in profiles if they are absent.
//
// With no import step this is where a working configuration comes from on a
// blank database. It does not overwrite: an edited profile stays edited across
// restarts.
func (s *Store) SeedDefaultProfiles(ctx context.Context) (int, error) {
	seeded := 0
	for _, engine := range discovery.All() {
		created, err := s.seedProfiles(ctx, "discovery", engine.Spec())
		if err != nil {
			return seeded, err
		}
		seeded += created
	}
	for _, engine := range scan.All() {
		created, err := s.seedProfiles(ctx, "scan", engine.Spec())
		if err != nil {
			return seeded, err
		}
		seeded += created
	}
	return seeded, nil
}

func (s *Store) seedProfiles(ctx context.Context, kind string, spec engines.Spec) (int, error) {
	seeded := 0
	for _, profile := range spec.BuiltInProfiles() {
		created, err := s.seedProfile(ctx, kind, spec.Name, profile)
		if err != nil {
			return seeded, err
		}
		if created {
			seeded++
		}
	}
	return seeded, nil
}

func (s *Store) seedProfile(ctx context.Context, kind, engine string, preset engines.DefaultProfile) (bool, error) {
	profile := api.Profile{
		Kind:    kind,
		Engine:  engine,
		Name:    preset.Name,
		Config:  preset.Config,
		Comment: preset.Comment,
		Paths:   preset.Paths,
	}

	var count int64
	err := s.DB(ctx).Model(&models.EngineProfile{}).
		Where("kind = ? AND engine = ? AND name = ?", kind, engine, profile.Name).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("check profile %s: %w", profile.ID(), err)
	}
	if count > 0 {
		return false, nil
	}

	if _, err := s.SaveProfile(ctx, profile); err != nil {
		return false, err
	}
	return true, nil
}

// specFor resolves an engine from whichever registry the kind names.
func specFor(kind, engine string) (engines.Spec, error) {
	switch kind {
	case "discovery":
		found, err := discovery.Get(engine)
		if err != nil {
			return engines.Spec{}, err
		}
		return found.Spec(), nil
	case "scan":
		found, err := scan.Get(engine)
		if err != nil {
			return engines.Spec{}, err
		}
		return found.Spec(), nil
	default:
		return engines.Spec{}, fmt.Errorf(
			"unknown profile kind %q: expected discovery or scan", kind)
	}
}

func splitProfileID(id string) (kind, engine, name string, err error) {
	parts := strings.Split(id, ":")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf(
			"profile %q is not addressed as kind:engine:name, such as scan:nuclei:safe", id)
	}
	return parts[0], parts[1], parts[2], nil
}
