package store

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// FindingOpts selects findings across runs.
type FindingOpts struct {
	Scan     []string `flag:"scan" help:"Only findings from these runs (id or name)"`
	Target   []string `flag:"target" help:"Only findings associated with these stable target IDs"`
	Severity []string `flag:"severity" help:"Only these severities"`
	Host     []string `flag:"host" help:"Only these hosts"`
	Template []string `flag:"template" help:"Only these template ids"`
	Tag      []string `flag:"tag" help:"Only findings carrying any of these tags; prefix ! to exclude"`
	Resource []string `flag:"resource" help:"Only findings about these resources (ulid or provider/scope/uid)"`
	Search   string   `flag:"search" help:"Substring match on check, resource or account"`
	Sort     string   `flag:"sort" help:"Sort by severity, check, resource, account or reported" default:"severity"`
	Order    string   `flag:"order" help:"Sort direction (asc or desc)" default:"asc"`
	Limit    int      `flag:"limit" help:"Most N findings" default:"500"`
	Offset   int      `flag:"offset" help:"Skip the first N findings"`
}

// GetFinding returns one persisted finding by its database identity.
func (s *Store) GetFinding(ctx context.Context, id string) (api.Finding, error) {
	var row models.Finding
	err := s.DB(ctx).Where("id = ?", id).First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return api.Finding{}, NotFound("finding", id)
		}
		return api.Finding{}, fmt.Errorf("get finding %s: %w", id, err)
	}
	resources, err := s.findingResources(ctx, []string{row.ID})
	if err != nil {
		return api.Finding{}, err
	}
	return row.Document(resources[row.ID]), nil
}

func (o FindingOpts) Validate() error {
	switch o.Sort {
	case "", "severity", "check", "resource", "account", "reported":
	default:
		return fmt.Errorf("unknown finding sort %q", o.Sort)
	}
	switch strings.ToLower(o.Order) {
	case "", "asc", "desc":
	default:
		return fmt.Errorf("unknown finding sort order %q: expected asc or desc", o.Order)
	}
	if o.Limit < 0 || o.Offset < 0 {
		return fmt.Errorf("finding limit and offset cannot be negative")
	}
	return nil
}

func (o FindingOpts) Scope(db *gorm.DB) (*gorm.DB, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if len(o.Scan) > 0 {
		db = db.Where(
			"scan_id::text = ANY(?) OR scan_id IN (SELECT id FROM scans WHERE name = ANY(?))",
			stringArray(o.Scan), stringArray(o.Scan))
	}
	for _, filter := range []struct {
		column string
		values []string
	}{
		{"target_id", o.Target},
		{"severity", o.Severity},
		{"host", o.Host},
		{"check_id", o.Template},
	} {
		if len(filter.values) > 0 {
			db = db.Where(filter.column+" = ANY(?)", stringArray(filter.values))
		}
	}
	if len(o.Tag) > 0 {
		db = tagPredicate(db, "tags", o.Tag)
	}
	if len(o.Resource) > 0 {
		ids := stringArray(o.Resource)
		db = db.Where(`resource_id IN (
			SELECT id FROM resources
			WHERE id::text = ANY(?) OR (provider || '/' || scope || '/' || uid) = ANY(?)
			   OR name = ANY(?) OR uid = ANY(?))`, ids, ids, ids, ids)
	}
	if o.Search != "" {
		pattern := "%" + o.Search + "%"
		db = db.Where(`finding_info ->> 'title' ILIKE ? OR check_id ILIKE ? OR host ILIKE ? OR matched_at ILIKE ?
			OR resource_id IN (SELECT id FROM resources WHERE name ILIKE ? OR uid ILIKE ?)`,
			pattern, pattern, pattern, pattern, pattern, pattern)
	}
	return db, nil
}

// ListFindings returns the findings a selector matches.
func (s *Store) ListFindings(ctx context.Context, opts FindingOpts) ([]api.Finding, error) {
	rows, _, err := s.listFindings(ctx, opts, false)
	return rows, err
}

// ListFindingsPaged returns a server-sorted page and the filtered total.
func (s *Store) ListFindingsPaged(ctx context.Context, opts FindingOpts) (api.FindingPage, error) {
	rows, total, err := s.listFindings(ctx, opts, true)
	if err != nil {
		return api.FindingPage{}, err
	}
	return api.FindingPage{Data: rows, Page: api.PageInfo{
		Limit: opts.Limit, Offset: opts.Offset, Total: total,
	}}, nil
}

func (s *Store) listFindings(ctx context.Context, opts FindingOpts, count bool) ([]api.Finding, int64, error) {
	query, err := opts.Scope(s.DB(ctx).Model(&models.Finding{}))
	if err != nil {
		return nil, 0, err
	}
	var total int64
	if count {
		if err := query.Session(&gorm.Session{}).Count(&total).Error; err != nil {
			return nil, 0, fmt.Errorf("count findings: %w", err)
		}
	}
	query = query.Order(findingOrder(opts))
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		query = query.Offset(opts.Offset)
	}

	var rows []models.Finding
	if err := query.Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("list findings: %w", err)
	}
	findings, err := s.documents(ctx, rows)
	if err != nil {
		return nil, 0, err
	}
	return findings, total, nil
}

func findingOrder(opts FindingOpts) string {
	direction := "ASC"
	if strings.EqualFold(opts.Order, "desc") {
		direction = "DESC"
	}
	column := map[string]string{
		"check":    `COALESCE(finding_info ->> 'title', check_id) COLLATE "C"`,
		"resource": `matched_at COLLATE "C"`,
		"account":  `host COLLATE "C"`,
		"reported": `"time"`,
	}[opts.Sort]
	if column == "" {
		// Ranked rather than ordered by severity_id directly. OCSF numbers the
		// scale upwards — critical is 5 — and recon's listings have always meant
		// ascending as most-severe-first, so sorting on the id would silently
		// reverse every default listing.
		column = severityRank
	}
	return column + " " + direction + ", scan_id DESC, line_no ASC"
}
