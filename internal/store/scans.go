package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// ScanOpts selects scan runs.
type ScanOpts struct {
	Engine   []string `flag:"engine" help:"Only runs of these engines"`
	Profile  []string `flag:"profile" help:"Only runs of these profiles"`
	Phase    []string `flag:"phase" help:"Only runs in these phases (queued, running, completed, failed, cancelled)"`
	Severity []string `flag:"severity" help:"Only runs that found at least one finding of these severities"`
	Since    string   `flag:"since" help:"Only runs started since this time (RFC3339 or a duration such as 24h)"`
	Limit    int      `flag:"limit" help:"Most recent N runs" default:"100"`
}

// Scope pushes the selector into SQL.
func (o ScanOpts) Scope(db *gorm.DB) (*gorm.DB, error) {
	if len(o.Engine) > 0 {
		db = db.Where("engine = ANY(?)", stringArray(o.Engine))
	}
	if len(o.Profile) > 0 {
		db = db.Where("profile = ANY(?)", stringArray(o.Profile))
	}
	if len(o.Phase) > 0 {
		db = db.Where("phase = ANY(?)", stringArray(o.Phase))
	}
	// A run "has" a severity when its denormalised counts record more than zero
	// of it, which is why those counts are on the row at all.
	for _, severity := range o.Severity {
		db = db.Where("COALESCE((severities ->> ?)::int, 0) > 0", severity)
	}
	if o.Since != "" {
		since, err := parseSince(o.Since)
		if err != nil {
			return nil, err
		}
		db = db.Where("started_at >= ?", since)
	}
	return db, nil
}

// ListScans returns the runs a selector matches, newest first.
func (s *Store) ListScans(ctx context.Context, opts ScanOpts) ([]api.Scan, error) {
	query, err := opts.Scope(s.DB(ctx))
	if err != nil {
		return nil, err
	}
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}

	var rows []models.Scan
	if err := query.Order("started_at DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}

	scans := make([]api.Scan, 0, len(rows))
	for _, row := range rows {
		counts, err := s.findingCount(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		hosts, err := s.scanHosts(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		scans = append(scans, row.Document(counts, hosts, selectorLabel(row)))
	}
	return scans, nil
}

// GetScan returns one run.
func (s *Store) GetScan(ctx context.Context, id string) (api.Scan, error) {
	row, err := s.scanRow(ctx, id)
	if err != nil {
		return api.Scan{}, err
	}
	counts, err := s.findingCount(ctx, row.ID)
	if err != nil {
		return api.Scan{}, err
	}
	hosts, err := s.scanHosts(ctx, row.ID)
	if err != nil {
		return api.Scan{}, err
	}
	return row.Document(counts, hosts, selectorLabel(row)), nil
}

// scanRow resolves a run by id or by name, because a name is what the results
// file is called and what anyone reading the runs list will type.
func (s *Store) scanRow(ctx context.Context, id string) (models.Scan, error) {
	var row models.Scan
	err := s.DB(ctx).Where("id::text = ? OR name = ?", id, id).First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return models.Scan{}, NotFound("scan", id)
		}
		return models.Scan{}, fmt.Errorf("get scan %s: %w", id, err)
	}
	return row, nil
}

func (s *Store) findingCount(ctx context.Context, scanID string) (int, error) {
	var count int64
	err := s.DB(ctx).Model(&models.Finding{}).Where("scan_id = ?", scanID).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("count findings for %s: %w", scanID, err)
	}
	return int(count), nil
}

func (s *Store) scanHosts(ctx context.Context, scanID string) ([]string, error) {
	var hosts []string
	err := s.DB(ctx).Model(&models.Finding{}).
		Where("scan_id = ?", scanID).
		Distinct().Order("host").Pluck("host", &hosts).Error
	if err != nil {
		return nil, fmt.Errorf("hosts for scan %s: %w", scanID, err)
	}
	return hosts, nil
}

// selectorLabel renders the stored selector back into the phrase the UI shows.
// It is derived rather than stored so that a change to how selectors read does
// not need a migration.
func selectorLabel(row models.Scan) string {
	return TargetOptsFrom(row.Selector.Get()).Describe()
}

// CreateScan records a run before it starts, so a crashed process still leaves
// evidence that something was attempted.
func (s *Store) CreateScan(ctx context.Context, scan models.Scan) (models.Scan, error) {
	if scan.StartedAt.IsZero() {
		scan.StartedAt = time.Now()
	}
	if scan.Phase == "" {
		scan.Phase = string(api.PhaseQueued)
	}
	if err := s.DB(ctx).Create(&scan).Error; err != nil {
		return models.Scan{}, fmt.Errorf("create scan: %w", err)
	}
	return scan, nil
}

// UpdateScan writes the run's terminal state.
func (s *Store) UpdateScan(ctx context.Context, scan models.Scan) error {
	err := s.DB(ctx).Model(&models.Scan{}).Where("id = ?", scan.ID).Updates(map[string]any{
		"phase":          scan.Phase,
		"finished_at":    scan.FinishedAt,
		"exit_code":      scan.ExitCode,
		"error":          scan.Error,
		"command":        scan.Command,
		"stats":          scan.Stats,
		"severities":     scan.Severities,
		"result_path":    scan.ResultPath,
		"engine_version": scan.EngineVersion,
		"endpoint_count": scan.EndpointCount,
	}).Error
	if err != nil {
		return fmt.Errorf("update scan %s: %w", scan.ID, err)
	}
	return nil
}

// SaveFindings writes a run's findings in the order the engine emitted them.
func (s *Store) SaveFindings(ctx context.Context, scanID string, findings []api.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	rows := make([]models.Finding, 0, len(findings))
	for i, finding := range findings {
		rows = append(rows, models.FindingFrom(scanID, i+1, finding))
	}
	// Batched: a broad scan can produce tens of thousands of findings, and one
	// statement per row would dominate the run's wall clock.
	if err := s.DB(ctx).CreateInBatches(rows, 500).Error; err != nil {
		return fmt.Errorf("save findings for %s: %w", scanID, err)
	}
	return nil
}

// FindingOpts selects findings across runs.
type FindingOpts struct {
	Scan     []string `flag:"scan" help:"Only findings from these runs (id or name)"`
	Severity []string `flag:"severity" help:"Only these severities"`
	Host     []string `flag:"host" help:"Only these hosts"`
	Template []string `flag:"template" help:"Only these template ids"`
	Tag      []string `flag:"tag" help:"Only findings carrying any of these tags"`
	Limit    int      `flag:"limit" help:"Most N findings" default:"500"`
}

// ListFindings returns the findings a selector matches.
func (s *Store) ListFindings(ctx context.Context, opts FindingOpts) ([]api.Finding, error) {
	query := s.DB(ctx).Model(&models.Finding{})

	if len(opts.Scan) > 0 {
		// Accept either form, matching GetScan.
		query = query.Where(
			"scan_id::text = ANY(?) OR scan_id IN (SELECT id FROM scans WHERE name = ANY(?))",
			stringArray(opts.Scan), stringArray(opts.Scan))
	}
	if len(opts.Severity) > 0 {
		query = query.Where("severity = ANY(?)", stringArray(opts.Severity))
	}
	if len(opts.Host) > 0 {
		query = query.Where("host = ANY(?)", stringArray(opts.Host))
	}
	if len(opts.Template) > 0 {
		query = query.Where("template_id = ANY(?)", stringArray(opts.Template))
	}
	if len(opts.Tag) > 0 {
		query = query.Where("tags && ?", stringArray(opts.Tag))
	}
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}

	var rows []models.Finding
	if err := query.Order("scan_id, line_no").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}

	findings := make([]api.Finding, 0, len(rows))
	for _, row := range rows {
		findings = append(findings, row.Document())
	}
	return findings, nil
}
