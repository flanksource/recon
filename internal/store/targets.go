package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/schema"
)

// hostOrder sorts by byte value rather than the database's default collation.
// The TypeScript store sorted hosts with localeCompare, which agrees with byte
// order across every hostname the schema's ^[a-z0-9][a-z0-9.-]*$ pattern allows;
// pinning the collation here keeps that true regardless of how the cluster was
// initialised.
const hostOrder = `host COLLATE "C" ASC`

// ListTargets returns the targets a selector matches, ordered by host.
func (s *Store) ListTargets(ctx context.Context, opts TargetOpts) ([]api.TargetDocument, error) {
	query, err := opts.Scope(s.DB(ctx))
	if err != nil {
		return nil, err
	}

	var rows []models.Target
	if err := query.Order(hostOrder).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list targets: %w", err)
	}

	documents := make([]api.TargetDocument, 0, len(rows))
	for _, row := range rows {
		document := row.Document()
		matches, err := opts.MatchesTags(document.Tags)
		if err != nil {
			return nil, err
		}
		if matches {
			documents = append(documents, document)
		}
	}
	return documents, nil
}

// GetTarget returns one target.
func (s *Store) GetTarget(ctx context.Context, host string) (api.TargetDocument, error) {
	var row models.Target
	err := s.DB(ctx).Where("host = ?", host).First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return api.TargetDocument{}, NotFound("target", host)
		}
		return api.TargetDocument{}, fmt.Errorf("get target %s: %w", host, err)
	}
	return row.Document(), nil
}

// SaveTarget writes a whole document, machine-owned sections included. This is
// the import and observation-merge path; user edits go through UpdateCurated.
func (s *Store) SaveTarget(ctx context.Context, document api.TargetDocument) error {
	if err := validate(document); err != nil {
		return err
	}

	row := models.TargetFromDocument(document)
	err := s.DB(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "host"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"class", "app", "cluster", "source", "profiles", "ports", "tags",
			"notes", "reason", "observed", "network", "http", "tech", "tls",
			"scan", "updated_at",
		}),
	}).Create(&row).Error
	if err != nil {
		return fmt.Errorf("save target %s: %w", document.Host, err)
	}
	return nil
}

// CreateTarget adds a host to the inventory with only its curated fields set.
//
// This is how a host a sweep found becomes a target: discovery records what it
// sees but never classifies it, because a class is a judgement about what a
// host is for. An existing host is refused rather than overwritten — a create
// that silently replaced a curated record would discard someone's work.
func (s *Store) CreateTarget(ctx context.Context, host string, curated api.Curated) (api.TargetDocument, error) {
	row := models.Target{Host: host}
	row.ApplyCurated(curated)

	document := row.Document()
	if err := validate(document); err != nil {
		return api.TargetDocument{}, err
	}

	result := s.DB(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row)
	if result.Error != nil {
		return api.TargetDocument{}, fmt.Errorf("create target %s: %w", host, result.Error)
	}
	if result.RowsAffected == 0 {
		return api.TargetDocument{}, fmt.Errorf("target %s is already in the inventory", host)
	}
	return document, nil
}

// EnsureDiscoveredTarget creates the conservative inventory record used for a
// newly observed identity, and returns an existing record unchanged.
func (s *Store) EnsureDiscoveredTarget(ctx context.Context, host string) (api.TargetDocument, error) {
	row := models.Target{Host: host}
	row.ApplyCurated(api.Curated{
		Class: api.ClassUnclassified, Source: "discovery",
		Profiles: []string{"safe"}, Tags: []string{},
	})
	if err := validate(row.Document()); err != nil {
		return api.TargetDocument{}, err
	}
	if err := s.DB(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
		return api.TargetDocument{}, fmt.Errorf("ensure discovered target %s: %w", host, err)
	}
	return s.GetTarget(ctx, host)
}

// UpdateCurated replaces only the editable fields and returns the stored
// document. Machine-owned sections are read back from the row and re-applied, so
// an edit can never clobber an observation — the property the TypeScript store
// guaranteed by spreading the existing document underneath the curated one.
func (s *Store) UpdateCurated(ctx context.Context, host string, curated api.Curated) (api.TargetDocument, error) {
	var stored api.TargetDocument

	err := s.DB(ctx).Transaction(func(tx *gorm.DB) error {
		var row models.Target
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("host = ?", host).First(&row).Error; err != nil {
			if IsNotFound(err) {
				return NotFound("target", host)
			}
			return err
		}

		row.ApplyCurated(curated)
		document := row.Document()
		if err := validate(document); err != nil {
			return err
		}

		if err := tx.Model(&models.Target{}).Where("host = ?", host).Updates(map[string]any{
			"class":      row.Class,
			"app":        row.App,
			"cluster":    row.Cluster,
			"source":     row.Source,
			"profiles":   row.Profiles,
			"ports":      row.Ports,
			"tags":       row.Tags,
			"notes":      row.Notes,
			"reason":     row.Reason,
			"updated_at": gorm.Expr("now()"),
		}).Error; err != nil {
			return err
		}

		stored = document
		return nil
	})
	if err != nil {
		if IsNotFound(err) {
			return api.TargetDocument{}, err
		}
		return api.TargetDocument{}, fmt.Errorf("update target %s: %w", host, err)
	}
	return stored, nil
}

// CountTargets is the import verification's cheap check.
func (s *Store) CountTargets(ctx context.Context) (int64, error) {
	var count int64
	if err := s.DB(ctx).Model(&models.Target{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("count targets: %w", err)
	}
	return count, nil
}

// TagVocabulary is every distinct tag in use, sorted. The UI offers it for
// filtering and bulk edits.
func (s *Store) TagVocabulary(ctx context.Context) ([]string, error) {
	return s.Vocabulary(ctx, TargetTags)
}

// Inventory assembles the listing the UI loads on start.
func (s *Store) Inventory(ctx context.Context) (api.Inventory, error) {
	rows, err := s.ListTargets(ctx, TargetOpts{})
	if err != nil {
		return api.Inventory{}, err
	}
	zones, err := s.ListZones(ctx)
	if err != nil {
		return api.Inventory{}, err
	}
	tags, err := s.TagVocabulary(ctx)
	if err != nil {
		return api.Inventory{}, err
	}
	return api.Inventory{
		Version:       api.TargetVersion,
		Zones:         zones,
		Rows:          rows,
		TagVocabulary: tags,
	}, nil
}

// validate runs the document through the JSON Schema before it reaches the
// database. The CHECK constraints are the backstop; this is what produces an
// error a human can act on, naming the offending field.
func validate(document api.TargetDocument) error {
	encoded, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode target %s: %w", document.Host, err)
	}
	return schema.ValidateTargetJSON(document.Host+".json", encoded)
}

// ---------------------------------------------------------------------- zones

// ListZones returns the configured DNS zones, sorted.
func (s *Store) ListZones(ctx context.Context) ([]string, error) {
	var rows []models.Zone
	if err := s.DB(ctx).Order(`zone COLLATE "C" ASC`).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	zones := make([]string, 0, len(rows))
	for _, row := range rows {
		zones = append(zones, row.Zone)
	}
	return zones, nil
}

// ReplaceZones sets the zone list, removing any not named.
func (s *Store) ReplaceZones(ctx context.Context, zones []string) error {
	sorted := append([]string(nil), zones...)
	sort.Strings(sorted)

	return s.DB(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("1 = 1").Delete(&models.Zone{}).Error; err != nil {
			return fmt.Errorf("clear zones: %w", err)
		}
		if len(sorted) == 0 {
			return nil
		}
		rows := make([]models.Zone, 0, len(sorted))
		for _, zone := range sorted {
			rows = append(rows, models.Zone{Zone: zone})
		}
		if err := tx.Create(&rows).Error; err != nil {
			return fmt.Errorf("insert zones: %w", err)
		}
		return nil
	})
}
