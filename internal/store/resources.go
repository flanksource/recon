package store

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// ResourceOpts selects resources.
//
// A list filter rather than a stored selector, so it carries Scope and Validate
// but not the Empty/Describe/Map contract TargetOpts needs — those exist because
// a target selector is written onto a scan row and replayed, and this one never
// is. FindingOpts sets the same reduced precedent.
type ResourceOpts struct {
	IDs      []string `json:"ids,omitempty" flag:"id" help:"Only these resources (ulid or provider/scope/uid)"`
	Provider []string `json:"provider,omitempty" flag:"provider" help:"Only resources from these providers"`
	// Account is the `scope` column. Named for what it is to a reader — the
	// account, project or registry a resource lives in — rather than for the
	// column, and because Scope is already this type's query-narrowing method.
	Account  []string `json:"account,omitempty" flag:"account" help:"Only resources in these accounts, projects or registries"`
	Kind     []string `json:"kind,omitempty" flag:"kind" help:"Only these kinds (account, cloud-resource, artifact, endpoint)"`
	Type     []string `json:"type,omitempty" flag:"type" help:"Only these provider resource types; prefix ! to exclude"`
	Service  []string `json:"service,omitempty" flag:"service" help:"Only these provider services"`
	Region   []string `json:"region,omitempty" flag:"region" help:"Only these regions"`
	Target   []string `json:"target,omitempty" flag:"target" help:"Only resources reached through these stable target IDs"`
	Engine   []string `json:"engine,omitempty" flag:"engine" help:"Only resources described by these engines"`
	Tag      []string `json:"tag,omitempty" flag:"tag" help:"Only resources carrying any of these tags; prefix ! to exclude"`
	Label    []string `json:"label,omitempty" flag:"label" help:"Only resources carrying these key:value labels; prefix ! to exclude"`
	State    []string `json:"state,omitempty" flag:"state" help:"Only these states (present, absent)"`
	Severity []string `json:"severity,omitempty" flag:"severity" help:"Only resources with an open finding of these severities"`
	Status   []string `json:"status,omitempty" flag:"status" help:"Only resources that are failing, clean or unchecked"`
	Search   string   `json:"search,omitempty" flag:"search" help:"Substring match on name or uid"`
	Since    string   `json:"since,omitempty" flag:"since" help:"Only resources seen since this time (RFC3339 or a duration such as 24h)"`
	Sort     string   `json:"sort,omitempty" flag:"sort" help:"Sort by worst, name, type, account, region or findings" default:"worst"`
	Order    string   `json:"order,omitempty" flag:"order" help:"Sort direction (asc or desc)" default:"asc"`
	Limit    int      `json:"limit,omitempty" flag:"limit" help:"Most N resources" default:"100"`
	Offset   int      `json:"offset,omitempty" flag:"offset" help:"Skip the first N resources"`
}

// Resource status, which is a question about the checks rather than about the
// resource. `unchecked` is only answerable because passing checks are recorded:
// without them a clean resource and one nobody looked at are the same row.
const (
	ResourceFailing   = "failing"
	ResourceClean     = "clean"
	ResourceUnchecked = "unchecked"
)

func (o ResourceOpts) Validate() error {
	switch o.Sort {
	case "", "worst", "name", "type", "account", "region", "findings":
	default:
		return fmt.Errorf("unknown resource sort %q", o.Sort)
	}
	switch strings.ToLower(o.Order) {
	case "", "asc", "desc":
	default:
		return fmt.Errorf("unknown resource sort order %q: expected asc or desc", o.Order)
	}
	if o.Limit < 0 || o.Offset < 0 {
		return fmt.Errorf("resource limit and offset cannot be negative")
	}
	for _, state := range o.State {
		if state != api.ResourcePresent && state != api.ResourceAbsent {
			return fmt.Errorf("unknown state %q: expected %s or %s",
				state, api.ResourcePresent, api.ResourceAbsent)
		}
	}
	for _, status := range o.Status {
		switch status {
		case ResourceFailing, ResourceClean, ResourceUnchecked:
		default:
			return fmt.Errorf("unknown status %q: expected %s, %s or %s",
				status, ResourceFailing, ResourceClean, ResourceUnchecked)
		}
	}
	for _, severity := range o.Severity {
		if api.ParseSeverity(severity) == api.SeverityUnknown && severity != string(api.SeverityUnknown) {
			return fmt.Errorf("unknown severity %q", severity)
		}
	}
	if o.Since != "" {
		if _, err := parseSince(o.Since); err != nil {
			return err
		}
	}
	return nil
}

// Scope narrows a query to what the selector matches.
func (o ResourceOpts) Scope(db *gorm.DB) (*gorm.DB, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}

	if len(o.IDs) > 0 {
		db = db.Where("id::text = ANY(?) OR (provider || '/' || scope || '/' || uid) = ANY(?)",
			stringArray(o.IDs), stringArray(o.IDs))
	}
	for _, filter := range []struct {
		column string
		values []string
	}{
		{"provider", o.Provider},
		{"scope", o.Account},
		{"kind", o.Kind},
		{"service", o.Service},
		{"region", o.Region},
		{"state", o.State},
	} {
		if len(filter.values) > 0 {
			db = db.Where(filter.column+" = ANY(?)", stringArray(filter.values))
		}
	}
	// Overlap rather than equality: a resource two engines describe is one row,
	// and asking for either of them has to match it.
	if len(o.Engine) > 0 {
		db = db.Where("engines && ?", stringArray(o.Engine))
	}
	if len(o.Target) > 0 {
		db = db.Where("target_id = ANY(?)", stringArray(o.Target))
	}
	// Type honours `!` because the UI renders it as a tri-state control: the
	// browser reads `type` as negatable, and a server that took `!x` literally
	// would match nothing and look like a working exclusion.
	db = scalarPredicate(db, "type", o.Type)
	db = tagPredicate(db, "tags", o.Tag)
	var err error
	db, err = labelPredicate(db, "labels", o.Label)
	if err != nil {
		return nil, err
	}

	if o.Search != "" {
		pattern := "%" + o.Search + "%"
		db = db.Where("name ILIKE ? OR uid ILIKE ?", pattern, pattern)
	}
	if o.Since != "" {
		since, err := parseSince(o.Since)
		if err != nil {
			return nil, err
		}
		db = db.Where("last_seen >= ?", since)
	}

	if len(o.Severity) > 0 {
		db = db.Where(resourceHasState(stateIsOpen+" AND finding_states.severity = ANY(?)"),
			stringArray(o.Severity))
	}
	return o.scopeStatus(db), nil
}

func (o ResourceOpts) scopeStatus(db *gorm.DB) *gorm.DB {
	if len(o.Status) == 0 {
		return db
	}
	open := resourceHasState(stateIsOpen)
	any := resourceHasState("")

	var clauses []string
	for _, status := range o.Status {
		switch status {
		case ResourceFailing:
			clauses = append(clauses, open)
		case ResourceClean:
			clauses = append(clauses, "("+any+" AND NOT "+open+")")
		case ResourceUnchecked:
			clauses = append(clauses, "NOT "+any)
		}
	}
	return db.Where(joinOr(clauses))
}

func joinOr(clauses []string) string {
	joined := ""
	for index, clause := range clauses {
		if index > 0 {
			joined += " OR "
		}
		joined += clause
	}
	return joined
}

// resourceQuery selects the rows plus their open-finding counts.
//
// A lateral rather than a denormalised column, because the counts are not a
// property of the resource: they change with every later run and with a mute
// rule edit that never touches the resource at all, so a cached column would go
// quietly wrong with nothing to invalidate it. scans.severities is denormalised
// precisely because a finished scan is immutable and its counts never can.
//
// Lateral rather than a GROUP BY join so the aggregate runs once per returned
// row instead of over the whole table before the limit applies.
const resourceQuery = `
SELECT resources.*,
       COALESCE(open.total, 0) AS open_findings,
       COALESCE(open.severities, '{}'::jsonb) AS open_severities
FROM resources
LEFT JOIN LATERAL (
    SELECT SUM(counted.n)::int AS total,
           jsonb_object_agg(counted.severity, counted.n) AS severities
    FROM (
        SELECT severity, COUNT(*) AS n
        FROM finding_states
        WHERE finding_states.resource_id = resources.id AND ` + stateIsOpen + `
        GROUP BY severity
    ) counted
) open ON TRUE`

// resourceRow is a row of resourceQuery: the table plus its counts.
type resourceRow struct {
	models.Resource
	OpenFindings   int                         `gorm:"column:open_findings"`
	OpenSeverities models.JSON[map[string]int] `gorm:"column:open_severities"`
}

func (r resourceRow) Document() api.Resource {
	return r.Resource.Document(r.OpenFindings, r.OpenSeverities.Get())
}

// ListResources returns the resources a selector matches, with what is open
// against each.
func (s *Store) ListResources(ctx context.Context, opts ResourceOpts) ([]api.Resource, error) {
	rows, _, err := s.listResources(ctx, opts, false)
	return rows, err
}

// ListResourcesPaged is the same listing with the total the pager needs.
//
// Resources are the one entity worth paging: a target list is curated by hand
// and bounded by human effort, while resources are enumerated by a machine and
// bounded by nothing, and the tab is opened cold with no filter to narrow by.
func (s *Store) ListResourcesPaged(ctx context.Context, opts ResourceOpts) (api.ResourcePage, error) {
	rows, total, err := s.listResources(ctx, opts, true)
	if err != nil {
		return api.ResourcePage{}, err
	}
	return api.ResourcePage{Data: rows, Page: api.PageInfo{
		Limit: opts.Limit, Offset: opts.Offset, Total: total,
	}}, nil
}

func (s *Store) listResources(ctx context.Context, opts ResourceOpts, count bool) ([]api.Resource, int64, error) {
	scoped, err := opts.Scope(s.DB(ctx).Model(&models.Resource{}))
	if err != nil {
		return nil, 0, err
	}

	var total int64
	if count {
		if err := scoped.Session(&gorm.Session{}).Count(&total).Error; err != nil {
			return nil, 0, fmt.Errorf("count resources: %w", err)
		}
	}

	query, err := opts.Scope(s.DB(ctx).Table("(" + resourceQuery + ") resources"))
	if err != nil {
		return nil, 0, err
	}
	// COLLATE "C" for the reason the target listing uses it: byte order is
	// stable, where the database's default collation is not.
	query = query.Order(resourceOrder(opts))
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}
	if opts.Offset > 0 {
		query = query.Offset(opts.Offset)
	}

	var rows []resourceRow
	if err := query.Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("list resources: %w", err)
	}

	resources := make([]api.Resource, 0, len(rows))
	for _, row := range rows {
		resources = append(resources, row.Document())
	}
	return resources, total, nil
}

func resourceOrder(opts ResourceOpts) string {
	direction := "ASC"
	if strings.EqualFold(opts.Order, "desc") {
		direction = "DESC"
	}
	columns := map[string]string{
		"name":     `name COLLATE "C"`,
		"type":     `type COLLATE "C"`,
		"account":  `scope COLLATE "C"`,
		"region":   `region COLLATE "C"`,
		"findings": "open_findings",
	}
	column := columns[opts.Sort]
	if column == "" {
		column = `CASE
			WHEN COALESCE((open_severities->>'critical')::int, 0) > 0 THEN 0
			WHEN COALESCE((open_severities->>'high')::int, 0) > 0 THEN 1
			WHEN COALESCE((open_severities->>'medium')::int, 0) > 0 THEN 2
			WHEN COALESCE((open_severities->>'low')::int, 0) > 0 THEN 3
			WHEN COALESCE((open_severities->>'info')::int, 0) > 0 THEN 4
			ELSE 5 END`
	}
	return column + " " + direction + `, name COLLATE "C" ASC, uid COLLATE "C" ASC`
}

// GetResource resolves a resource by its ulid or by its natural key.
//
// Both, because a ulid is what a row href carries and provider/scope/uid is what
// a person reading a finding would type. Matching GetScan, which takes an id or
// a run name for the same reason.
func (s *Store) GetResource(ctx context.Context, id string) (api.Resource, error) {
	opts := ResourceOpts{IDs: []string{id}, Limit: 2}
	found, _, err := s.listResources(ctx, opts, false)
	if err != nil {
		return api.Resource{}, err
	}
	switch len(found) {
	case 0:
		return api.Resource{}, NotFound("resource", id)
	case 1:
		return found[0], nil
	default:
		// Ambiguity is not a miss and must not be resolved by picking. One
		// project id is the uid of several resources, so the caller has to say
		// which — the same rule the Mission Control resolver applies.
		return api.Resource{}, fmt.Errorf(
			"%q matches more than one resource; address it as provider/scope/uid or by its id", id)
	}
}

// upsertResources records what a run examined and returns the id of each.
//
// The ids are what findings are stamped with, so this has to run before the
// findings are written.
func upsertResources(db *gorm.DB, scanID, engine string, seen time.Time, resources []api.Resource) (map[api.ResourceKey]string, error) {
	if len(resources) == 0 {
		return map[api.ResourceKey]string{}, nil
	}
	if engine == "" {
		return nil, fmt.Errorf("save resources for %s: a run needs an engine", scanID)
	}

	rows := make([]models.Resource, 0, len(resources))
	for _, resource := range resources {
		if err := resource.Key().Validate(); err != nil {
			return nil, fmt.Errorf("save resources for %s: %w", scanID, err)
		}
		rows = append(rows, models.ResourceFrom(scanID, engine, seen, resource))
	}
	// Locks are taken in this order, so two engines finalizing over an
	// overlapping estate must agree on it or deadlock. The engine's own report
	// order is not an agreement; the identity is.
	slices.SortFunc(rows, func(a, b models.Resource) int {
		return cmp.Or(
			strings.Compare(a.Provider, b.Provider),
			strings.Compare(a.Scope, b.Scope),
			strings.Compare(a.UID, b.UID))
	})

	err := db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{{Name: "provider"}, {Name: "scope"}, {Name: "uid"}},
			DoUpdates: clause.Assignments(map[string]any{
				// Never regress on a replayed or out-of-order run.
				"first_seen": gorm.Expr("LEAST(resources.first_seen, EXCLUDED.first_seen)"),
				"last_seen":  gorm.Expr("GREATEST(resources.last_seen, EXCLUDED.last_seen)"),
				"last_scan_id": gorm.Expr(
					"CASE WHEN EXCLUDED.last_seen >= resources.last_seen THEN EXCLUDED.last_scan_id ELSE resources.last_scan_id END"),
				// A check that reported no metadata must not blank what another
				// check already supplied for the same resource.
				"name":         gorm.Expr("COALESCE(NULLIF(EXCLUDED.name, ''), resources.name)"),
				"type":         gorm.Expr("COALESCE(NULLIF(EXCLUDED.type, ''), resources.type)"),
				"service":      gorm.Expr("COALESCE(NULLIF(EXCLUDED.service, ''), resources.service)"),
				"region":       gorm.Expr("COALESCE(NULLIF(EXCLUDED.region, ''), resources.region)"),
				"kind":         gorm.Expr("EXCLUDED.kind"),
				"account_name": gorm.Expr("COALESCE(NULLIF(EXCLUDED.account_name, ''), resources.account_name)"),
				"org_uid":      gorm.Expr("COALESCE(NULLIF(EXCLUDED.org_uid, ''), resources.org_uid)"),
				"org_name":     gorm.Expr("COALESCE(NULLIF(EXCLUDED.org_name, ''), resources.org_name)"),
				"config_type":  gorm.Expr("COALESCE(NULLIF(EXCLUDED.config_type, ''), resources.config_type)"),
				"external_ids": gorm.Expr("CASE WHEN cardinality(EXCLUDED.external_ids) > 0 THEN EXCLUDED.external_ids ELSE resources.external_ids END"),
				"tags":         gorm.Expr("CASE WHEN cardinality(EXCLUDED.tags) > 0 THEN EXCLUDED.tags ELSE resources.tags END"),
				"labels":       gorm.Expr("COALESCE(EXCLUDED.labels, resources.labels)"),
				"metadata":     gorm.Expr("COALESCE(EXCLUDED.metadata, resources.metadata)"),
				// Unioned, never replaced. The identity excludes the engine, so
				// this row serves all of them, and the absence sweep reads this
				// column to decide whose view it may judge: overwriting it hid
				// the resource from every engine but the last one to run.
				"engines": gorm.Expr(
					"CASE WHEN resources.engines @> EXCLUDED.engines THEN resources.engines" +
						" ELSE resources.engines || EXCLUDED.engines END"),
				"target_id":    gorm.Expr("COALESCE(EXCLUDED.target_id, resources.target_id)"),
				// Seeing it again is what makes it present again, and clears when
				// it was not.
				"state":      gorm.Expr("'present'"),
				"absent_at":  gorm.Expr("NULL"),
				"updated_at": gorm.Expr("now()"),
			}),
		},
		// Explicit, because on a DO UPDATE gorm returns the conflicting row's id
		// only when it is asked to: without this the map would be missing an
		// entry for every resource that already existed.
		clause.Returning{Columns: []clause.Column{
			{Name: "id"}, {Name: "provider"}, {Name: "scope"}, {Name: "uid"},
		}},
	).CreateInBatches(&rows, 500).Error
	if err != nil {
		return nil, fmt.Errorf("save resources for %s: %w", scanID, err)
	}

	ids := make(map[api.ResourceKey]string, len(rows))
	for _, row := range rows {
		ids[api.ResourceKey{Provider: row.Provider, Scope: row.Scope, UID: row.UID}] = row.ID
	}
	return ids, nil
}
