package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// ProbeOpts selects liveness sweeps.
type ProbeOpts struct {
	Host  []string `flag:"host" help:"Only sweeps that probed these hosts"`
	Phase []string `flag:"phase" help:"Only sweeps in these phases (running, done, failed, cancelled)"`
	Since string   `flag:"since" help:"Only sweeps started since this time (RFC3339 or a duration such as 24h)"`
	Limit int      `flag:"limit" help:"Most recent N sweeps" default:"50"`
}

// Scope pushes the selector into SQL.
func (o ProbeOpts) Scope(db *gorm.DB) (*gorm.DB, error) {
	if len(o.Phase) > 0 {
		db = db.Where("phase = ANY(?)", stringArray(o.Phase))
	}
	if len(o.Host) > 0 {
		// EXISTS rather than a join: a sweep covers the whole estate, and
		// joining would return one row per matching host.
		db = db.Where(
			"EXISTS (SELECT 1 FROM probe_results WHERE probe_results.probe_id = probes.id AND probe_results.host = ANY(?))",
			stringArray(o.Host))
	}
	if o.Since != "" {
		since, err := parseSince(o.Since)
		if err != nil {
			return nil, err
		}
		db = db.Where("ran_at >= ?", since)
	}
	return db, nil
}

// ListProbes returns the sweeps a selector matches, newest first.
//
// Results are not loaded: a sweep covers the whole estate, and the listing only
// needs the counts.
func (s *Store) ListProbes(ctx context.Context, opts ProbeOpts) ([]api.ProbeRun, error) {
	query, err := opts.Scope(s.DB(ctx).Model(&models.Probe{}))
	if err != nil {
		return nil, err
	}
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}

	var rows []models.Probe
	if err := query.Order("ran_at DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list probes: %w", err)
	}
	if len(rows) == 0 {
		return []api.ProbeRun{}, nil
	}

	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	counts, err := s.probeCounts(ctx, ids)
	if err != nil {
		return nil, err
	}

	runs := make([]api.ProbeRun, 0, len(rows))
	for _, row := range rows {
		label, err := probeSelectorLabel(row)
		if err != nil {
			return nil, err
		}
		runs = append(runs, row.Document(nil, counts[row.ID], label))
	}
	return runs, nil
}

// probeCounts aggregates every listed run in one statement.
//
// One query for the whole page rather than one per row: the runs list is polled
// while a sweep is going, and a count per row would multiply that by the page
// size on every tick.
func (s *Store) probeCounts(ctx context.Context, ids []string) (map[string]models.ProbeCounts, error) {
	var rows []struct {
		ProbeID string
		Live    int
		Updated int
	}
	err := s.DB(ctx).Model(&models.ProbeResult{}).
		Select("probe_id, COUNT(*) FILTER (WHERE up) AS live, COUNT(*) FILTER (WHERE updated) AS updated").
		Where("probe_id::text = ANY(?)", stringArray(ids)).
		Group("probe_id").Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("count probe results: %w", err)
	}

	counts := make(map[string]models.ProbeCounts, len(rows))
	for _, row := range rows {
		counts[row.ProbeID] = models.ProbeCounts{Live: row.Live, Updated: row.Updated}
	}
	return counts, nil
}

// GetProbe returns one sweep with everything it saw.
func (s *Store) GetProbe(ctx context.Context, id string) (api.ProbeRun, error) {
	var row models.Probe
	if err := s.DB(ctx).Where("id::text = ?", id).First(&row).Error; err != nil {
		if IsNotFound(err) {
			return api.ProbeRun{}, NotFound("probe", id)
		}
		return api.ProbeRun{}, fmt.Errorf("get probe %s: %w", id, err)
	}

	var resultRows []models.ProbeResult
	if err := s.DB(ctx).Where("probe_id = ?", row.ID).Order("host").Find(&resultRows).Error; err != nil {
		return api.ProbeRun{}, fmt.Errorf("get probe results for %s: %w", id, err)
	}

	results := make([]api.ProbeResult, 0, len(resultRows))
	counts := models.ProbeCounts{}
	for _, result := range resultRows {
		results = append(results, result.Document())
		if result.Up {
			counts.Live++
		}
		if result.Updated {
			counts.Updated++
		}
	}

	label, err := probeSelectorLabel(row)
	if err != nil {
		return api.ProbeRun{}, err
	}
	return row.Document(results, counts, label), nil
}

// probeSelectorLabel renders the stored selector back into the phrase the UI
// shows. Derived rather than stored, matching scans: a change to how selectors
// read does not need a migration.
func probeSelectorLabel(row models.Probe) (string, error) {
	opts, err := TargetOptsFrom(row.Selector.Get())
	if err != nil {
		return "", fmt.Errorf("probe %s selector: %w", row.ID, err)
	}
	return opts.Describe(), nil
}

// CreateProbe records a sweep before it starts, so a crashed process still
// leaves evidence that something was attempted.
func (s *Store) CreateProbe(ctx context.Context, row *models.Probe) error {
	if row.RanAt.IsZero() {
		row.RanAt = time.Now()
	}
	if row.Phase == "" {
		row.Phase = string(api.PhaseRunning)
	}
	if err := s.DB(ctx).Create(row).Error; err != nil {
		return fmt.Errorf("create probe: %w", err)
	}
	return nil
}

// SaveProbeResult records what one host answered, as soon as it answered.
//
// Per host rather than per run: the run is readable while it is still going,
// which is what the dialog's live table and the inventory's per-row refresh
// both read. Upserted so a re-probed host in the same run overwrites rather
// than conflicting.
func (s *Store) SaveProbeResult(ctx context.Context, row models.ProbeResult) error {
	err := s.DB(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "probe_id"}, {Name: "host"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"url", "up", "status_code", "response_time_ms",
			"ip", "content_type", "error", "updated", "probed_at",
		}),
	}).Create(&row).Error
	if err != nil {
		return fmt.Errorf("save probe result for %s: %w", row.Host, err)
	}
	return nil
}

// FinishProbe writes a sweep's terminal state.
func (s *Store) FinishProbe(ctx context.Context, row models.Probe) error {
	phase := api.Phase(row.Phase)
	if !phase.Terminal() {
		return fmt.Errorf("finish probe %s: phase %q is not terminal", row.ID, phase)
	}

	result := s.DB(ctx).Model(&models.Probe{}).Where("id = ?", row.ID).Updates(map[string]any{
		"phase":       row.Phase,
		"finished_at": row.FinishedAt,
		"duration_ms": row.DurationMS,
		"error":       row.Error,
	})
	if result.Error != nil {
		return fmt.Errorf("finish probe %s: %w", row.ID, result.Error)
	}
	if result.RowsAffected != 1 {
		return NotFound("probe", row.ID)
	}
	return nil
}

// ProbeHistory returns what every sweep saw for one host, newest first. It is
// the query probe_results_host_idx exists for.
func (s *Store) ProbeHistory(ctx context.Context, host string, limit int) ([]api.ProbeResult, error) {
	query := s.DB(ctx).Model(&models.ProbeResult{}).Where("host = ?", host).Order("probed_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}

	var rows []models.ProbeResult
	if err := query.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("probe history for %s: %w", host, err)
	}

	results := make([]api.ProbeResult, 0, len(rows))
	for _, row := range rows {
		results = append(results, row.Document())
	}
	return results, nil
}
