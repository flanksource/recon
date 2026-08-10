package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// DiscoverOpts selects discovery sweeps.
type DiscoverOpts struct {
	Chain []string `json:"chain,omitempty" flag:"chain" help:"Only sweeps of these chains (full, targeted, explicit)"`
	Since string   `json:"since,omitempty" flag:"since" help:"Only sweeps since this time (RFC3339 or a duration such as 24h)"`
	Limit int      `json:"limit,omitempty" flag:"limit" help:"Most recent N sweeps" default:"50"`
}

// ListDiscoveries returns the sweeps a selector matches, newest first.
//
// Hosts are not loaded here: a sweep can see thousands, and the runs list only
// needs the counts.
func (s *Store) ListDiscoveries(ctx context.Context, opts DiscoverOpts) ([]api.Discover, error) {
	query := s.DB(ctx).Model(&models.Discovery{})
	if len(opts.Chain) > 0 {
		query = query.Where("chain = ANY(?)", stringArray(opts.Chain))
	}
	if opts.Since != "" {
		since, err := parseSince(opts.Since)
		if err != nil {
			return nil, err
		}
		query = query.Where("ran_at >= ?", since)
	}
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}

	var rows []models.Discovery
	if err := query.Order("ran_at DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list discoveries: %w", err)
	}

	sweeps := make([]api.Discover, 0, len(rows))
	for _, row := range rows {
		sweeps = append(sweeps, row.Document(nil))
	}
	return sweeps, nil
}

// CreateDiscovery records a sweep before it starts, so a crashed process still
// leaves evidence that something was attempted.
func (s *Store) CreateDiscovery(ctx context.Context, row *models.Discovery) error {
	if row.RanAt.IsZero() {
		row.RanAt = time.Now()
	}
	if err := s.DB(ctx).Create(row).Error; err != nil {
		return fmt.Errorf("create discovery: %w", err)
	}
	return nil
}

// FinishDiscovery writes a sweep's outcome.
func (s *Store) FinishDiscovery(ctx context.Context, row models.Discovery) error {
	err := s.DB(ctx).Model(&models.Discovery{}).Where("id = ?", row.ID).Updates(map[string]any{
		"duration_ms": row.DurationMs,
		"failed":      row.Failed,
		"error":       row.Error,
		"log":         row.Log,
	}).Error
	if err != nil {
		return fmt.Errorf("finish discovery %s: %w", row.ID, err)
	}
	return nil
}

// SaveDiscoveryHosts records what each engine saw.
func (s *Store) SaveDiscoveryHosts(ctx context.Context, rows []models.DiscoveryHost) error {
	if len(rows) == 0 {
		return nil
	}

	err := s.DB(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{
			{Name: "discovery_id"}, {Name: "host"}, {Name: "engine"},
		},
		DoUpdates: clause.AssignmentColumns([]string{"live", "probe"}),
	}).CreateInBatches(rows, 500).Error
	if err != nil {
		return fmt.Errorf("save discovery hosts: %w", err)
	}
	return nil
}

// GetDiscovery returns one sweep with the hosts it saw.
func (s *Store) GetDiscovery(ctx context.Context, id string) (api.Discover, error) {
	var row models.Discovery
	err := s.DB(ctx).Where("id::text = ?", id).First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return api.Discover{}, NotFound("discovery", id)
		}
		return api.Discover{}, fmt.Errorf("get discovery %s: %w", id, err)
	}

	hosts, err := s.DiscoveredHosts(ctx, row.ID)
	if err != nil {
		return api.Discover{}, err
	}
	return row.Document(hosts), nil
}

// Latest returns the most recent sweep, which is the cached view the UI opens
// with. It is not an error for there to be none.
func (s *Store) LatestDiscovery(ctx context.Context) (*api.Discover, error) {
	var row models.Discovery
	err := s.DB(ctx).Order("ran_at DESC").First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("latest discovery: %w", err)
	}

	hosts, err := s.DiscoveredHosts(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	sweep := row.Document(hosts)
	return &sweep, nil
}

// DiscoveredHosts returns what one sweep saw, collapsing the per-engine rows
// into one entry per host.
func (s *Store) DiscoveredHosts(ctx context.Context, discoveryID string) ([]api.DiscoveredHost, error) {
	var rows []models.DiscoveryHost
	err := s.DB(ctx).Where("discovery_id = ?", discoveryID).Order("host, engine").Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("hosts for discovery %s: %w", discoveryID, err)
	}
	if len(rows) == 0 {
		return []api.DiscoveredHost{}, nil
	}

	byHost := map[string]*api.DiscoveredHost{}
	var order []string
	for _, row := range rows {
		entry, seen := byHost[row.Host]
		if !seen {
			entry = &api.DiscoveredHost{Host: row.Host}
			byHost[row.Host] = entry
			order = append(order, row.Host)
		}
		entry.Engines = append(entry.Engines, row.Engine)
		entry.Live = entry.Live || row.Live
	}

	hosts := make([]api.DiscoveredHost, 0, len(order))
	for _, host := range order {
		hosts = append(hosts, *byHost[host])
	}
	return hosts, nil
}
