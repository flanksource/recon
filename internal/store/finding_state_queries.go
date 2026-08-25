package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// FindingStateOpts selects the current resource/check ledger.
type FindingStateOpts struct {
	Resource []string `json:"resource,omitempty" flag:"resource" help:"Only these resources"`
	Provider []string `json:"provider,omitempty" flag:"provider" help:"Only these providers"`
	Account  []string `json:"account,omitempty" flag:"account" help:"Only these accounts or projects"`
	Kind     []string `json:"kind,omitempty" flag:"kind" help:"Only these resource kinds"`
	Type     []string `json:"type,omitempty" flag:"type" help:"Only these resource types; prefix ! to exclude"`
	Service  []string `json:"service,omitempty" flag:"service" help:"Only these services"`
	Region   []string `json:"region,omitempty" flag:"region" help:"Only these regions"`
	Target   []string `json:"target,omitempty" flag:"target" help:"Only these target IDs"`
	Engine   []string `json:"engine,omitempty" flag:"engine" help:"Only these engines"`
	Tag      []string `json:"tag,omitempty" flag:"tag" help:"Only resources with these tags; prefix ! to exclude"`
	Label    []string `json:"label,omitempty" flag:"label" help:"Only resources with these key:value labels; prefix ! to exclude"`
	State    []string `json:"state,omitempty" flag:"state" help:"Only present or absent resources"`

	Check    []string `json:"check,omitempty" flag:"check" help:"Only these check IDs"`
	Status   []string `json:"status,omitempty" flag:"status" help:"Only open, resolved, muted or manual states"`
	Severity []string `json:"severity,omitempty" flag:"severity" help:"Only these severities"`
	Search   string   `json:"search,omitempty" flag:"search" help:"Substring match on check or resource"`
	Sort     string   `json:"sort,omitempty" flag:"sort" help:"Sort by severity, check, affected or last-seen" default:"severity"`
	Order    string   `json:"order,omitempty" flag:"order" help:"Sort direction" default:"asc"`
	Limit    int      `json:"limit,omitempty" flag:"limit" help:"Most N rows" default:"100"`
	Offset   int      `json:"offset,omitempty" flag:"offset" help:"Skip N rows"`
}

func (o FindingStateOpts) Validate() error {
	if o.Limit < 0 || o.Offset < 0 {
		return fmt.Errorf("finding state limit and offset cannot be negative")
	}
	for _, status := range o.Status {
		switch status {
		case api.StatusOpen, api.StatusResolved, api.StatusMuted, api.StatusManual:
		default:
			return fmt.Errorf("unknown finding status %q", status)
		}
	}
	switch o.Sort {
	case "", "severity", "check", "affected", "last-seen":
	default:
		return fmt.Errorf("unknown finding state sort %q", o.Sort)
	}
	if o.Order != "" && !strings.EqualFold(o.Order, "asc") && !strings.EqualFold(o.Order, "desc") {
		return fmt.Errorf("unknown finding state sort order %q", o.Order)
	}
	return nil
}

func (o FindingStateOpts) resourceOpts() ResourceOpts {
	return ResourceOpts{
		IDs: o.Resource, Provider: o.Provider, Account: o.Account, Kind: o.Kind,
		Type: o.Type, Service: o.Service, Region: o.Region, Target: o.Target,
		Tag: o.Tag, Label: o.Label, State: o.State,
	}
}

func (o FindingStateOpts) scope(db *gorm.DB, resources *gorm.DB) (*gorm.DB, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	db = db.Where("finding_states.resource_id IN (?)", resources).Where(stateIsFinding)
	if len(o.Engine) > 0 {
		db = db.Where("finding_states.engine = ANY(?)", stringArray(o.Engine))
	}
	if len(o.Check) > 0 {
		db = db.Where("finding_states.check_id = ANY(?)", stringArray(o.Check))
	}
	statuses := append([]string(nil), o.Status...)
	if slices.Contains(statuses, api.StatusOpen) && !slices.Contains(statuses, api.StatusManual) {
		statuses = append(statuses, api.StatusManual)
	}
	if len(statuses) > 0 {
		db = db.Where("finding_states.status = ANY(?)", stringArray(statuses))
	}
	if len(o.Severity) > 0 {
		db = db.Where("finding_states.severity = ANY(?)", stringArray(o.Severity))
	}
	if o.Search != "" {
		pattern := "%" + o.Search + "%"
		// The title arm reads the catalogue, which is keyed on exactly the pair
		// being matched, so it is a primary-key lookup per candidate row. It used
		// to correlate over `findings` — an unindexed ILIKE over every finding
		// ever recorded, re-run for each state considered — because the check's
		// title lived nowhere else.
		db = db.Where(`finding_states.check_id ILIKE ? OR finding_states.resource_id IN (
			SELECT id FROM resources WHERE name ILIKE ? OR uid ILIKE ?) OR EXISTS (
			SELECT 1 FROM checks c
			WHERE c.engine = finding_states.engine AND c.check_id = finding_states.check_id
			  AND c.name ILIKE ?)`, pattern, pattern, pattern, pattern)
	}
	return db, nil
}

func (s *Store) stateQuery(ctx context.Context, opts FindingStateOpts) (*gorm.DB, error) {
	resources, err := opts.resourceOpts().Scope(s.DB(ctx).Model(&models.Resource{}).Select("id"))
	if err != nil {
		return nil, err
	}
	return opts.scope(s.DB(ctx).Model(&models.FindingState{}), resources)
}

func (s *Store) ListFindingStatesPaged(ctx context.Context, opts FindingStateOpts) (api.FindingStatePage, error) {
	query, err := s.stateQuery(ctx, opts)
	if err != nil {
		return api.FindingStatePage{}, err
	}
	var total int64
	if err := query.Session(&gorm.Session{}).Count(&total).Error; err != nil {
		return api.FindingStatePage{}, fmt.Errorf("count finding states: %w", err)
	}
	query = query.Order(stateOrder(opts))
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		query = query.Offset(opts.Offset)
	}
	var rows []models.FindingState
	if err := query.Find(&rows).Error; err != nil {
		return api.FindingStatePage{}, fmt.Errorf("list finding states: %w", err)
	}
	data, err := s.hydrateFindingStates(ctx, rows)
	return api.FindingStatePage{Data: data, Page: api.PageInfo{Limit: opts.Limit, Offset: opts.Offset, Total: total}}, err
}

func (s *Store) ListFindingGroupsPaged(ctx context.Context, opts FindingStateOpts) (api.FindingGroupPage, error) {
	query, err := s.stateQuery(ctx, opts)
	if err != nil {
		return api.FindingGroupPage{}, err
	}
	base := query.Select(`finding_states.engine, finding_states.check_id, finding_states.status,
		COUNT(*) AS n, MAX(finding_states.last_seen) AS last_seen,
		MIN(CASE finding_states.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
			WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END) AS severity_rank`).
		Group("finding_states.engine, finding_states.check_id, finding_states.status")
	grouped := s.DB(ctx).Table("(?) state_counts", base).
		Select(`engine, check_id, SUM(n) AS affected, jsonb_object_agg(status, n) AS statuses,
			MIN(severity_rank) AS severity_rank, MAX(last_seen) AS last_seen`).
		Group("engine, check_id")
	var total int64
	if err := s.DB(ctx).Table("(?) finding_groups", grouped).Count(&total).Error; err != nil {
		return api.FindingGroupPage{}, fmt.Errorf("count finding groups: %w", err)
	}
	grouped = grouped.Order(groupOrder(opts))
	if opts.Limit > 0 {
		grouped = grouped.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		grouped = grouped.Offset(opts.Offset)
	}
	var rows []struct {
		Engine       string                      `gorm:"column:engine"`
		CheckID      string                      `gorm:"column:check_id"`
		Affected     int                         `gorm:"column:affected"`
		Statuses     models.JSON[map[string]int] `gorm:"column:statuses"`
		SeverityRank int                         `gorm:"column:severity_rank"`
		LastSeen     time.Time                   `gorm:"column:last_seen"`
	}
	if err := grouped.Scan(&rows).Error; err != nil {
		return api.FindingGroupPage{}, fmt.Errorf("list finding groups: %w", err)
	}
	engines := make([]string, 0, len(rows))
	checks := make([]string, 0, len(rows))
	for _, row := range rows {
		engines = append(engines, row.Engine)
		checks = append(checks, row.CheckID)
	}
	var titles []struct {
		Engine  string `gorm:"column:engine"`
		CheckID string `gorm:"column:check_id"`
		Name    string `gorm:"column:name"`
	}
	if len(rows) > 0 {
		if err := s.DB(ctx).Raw(`
			SELECT DISTINCT ON (scans.engine, findings.check_id)
			       scans.engine, findings.check_id AS check_id,
			       COALESCE(findings.finding_info ->> 'title', findings.check_id) AS name
			FROM findings JOIN scans ON scans.id = findings.scan_id AND scans.phase = 'done'
			WHERE scans.engine = ANY(?) AND findings.check_id = ANY(?)
			ORDER BY scans.engine, findings.check_id,
			         findings."time" DESC NULLS LAST, findings.scan_id DESC, findings.line_no DESC`,
			stringArray(engines), stringArray(checks)).Scan(&titles).Error; err != nil {
			return api.FindingGroupPage{}, fmt.Errorf("load finding group titles: %w", err)
		}
	}
	titleByCheck := make(map[string]string, len(titles))
	for _, title := range titles {
		titleByCheck[title.Engine+"\x00"+title.CheckID] = title.Name
	}
	severities := []api.Severity{api.SeverityCritical, api.SeverityHigh, api.SeverityMedium, api.SeverityLow, api.SeverityInfo, api.SeverityUnknown}
	data := make([]api.FindingGroup, 0, len(rows))
	for _, row := range rows {
		name := titleByCheck[row.Engine+"\x00"+row.CheckID]
		if name == "" {
			name = row.CheckID
		}
		data = append(data, api.FindingGroup{
			Engine: row.Engine, CheckID: row.CheckID, Name: name,
			Severity: severities[row.SeverityRank], Affected: row.Affected,
			Statuses: row.Statuses.Get(), LastSeen: row.LastSeen.Format(time.RFC3339),
		})
	}
	return api.FindingGroupPage{Data: data, Page: api.PageInfo{Limit: opts.Limit, Offset: opts.Offset, Total: total}}, nil
}

func (s *Store) ListInsightStates(ctx context.Context, opts FindingStateOpts) ([]api.InsightState, error) {
	query, err := s.stateQuery(ctx, opts)
	if err != nil {
		return nil, err
	}
	var rows []models.FindingState
	if err := query.Order("finding_states.resource_id, finding_states.engine, finding_states.check_id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list insight states: %w", err)
	}
	states, err := s.hydrateFindingStates(ctx, rows)
	if err != nil {
		return nil, err
	}
	insights := make([]api.InsightState, 0, len(states))
	var parentRows []models.Resource
	if err := s.DB(ctx).Where("kind = ?", api.KindAccount).Find(&parentRows).Error; err != nil {
		return nil, fmt.Errorf("list account resources for insight states: %w", err)
	}
	parents := make(map[string]api.Resource, len(parentRows))
	for _, row := range parentRows {
		parents[row.Provider+"\x00"+row.Scope] = row.Document(0, nil)
	}
	// One batch rather than a GetScan per state. This runs unbounded — the
	// uploader sets no limit — and GetScan is four queries that also read
	// scan_outputs.stdout and stderr, the megabytes that table exists to keep off
	// list paths, none of which the caller reads.
	scans, err := s.scansByID(ctx, states)
	if err != nil {
		return nil, err
	}
	for _, state := range states {
		if state.Resource == nil || state.Finding == nil {
			return nil, fmt.Errorf("finding state %s is missing its resource or evidence", state.ID)
		}
		scan, found := scans[state.LastScanID]
		if !found {
			return nil, fmt.Errorf("finding state %s names scan %s, which is gone", state.ID, state.LastScanID)
		}
		insight := api.InsightState{State: state, Resource: *state.Resource, Finding: *state.Finding, Scan: scan}
		if parent, found := parents[insight.Resource.Provider+"\x00"+insight.Resource.Scope]; found && parent.ID != insight.Resource.ID {
			insight.Parent = &parent
		}
		insights = append(insights, insight)
	}
	return insights, nil
}

func stateOrder(opts FindingStateOpts) string {
	direction := "ASC"
	if strings.EqualFold(opts.Order, "desc") {
		direction = "DESC"
	}
	column := map[string]string{"check": "check_id", "last-seen": "last_seen"}[opts.Sort]
	if column == "" {
		column = `CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END`
	}
	return column + " " + direction + ", resource_id ASC, engine ASC, check_id ASC"
}

func groupOrder(opts FindingStateOpts) string {
	direction := "ASC"
	if strings.EqualFold(opts.Order, "desc") {
		direction = "DESC"
	}
	column := map[string]string{
		"check": "check_id", "affected": "affected", "last-seen": "last_seen",
	}[opts.Sort]
	if column == "" {
		column = "severity_rank"
	}
	return column + " " + direction + ", engine ASC, check_id ASC"
}
