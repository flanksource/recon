package models

import (
	"time"

	"github.com/lib/pq"

	"github.com/flanksource/recon/internal/api"
)

// Resource is one row of the resources table.
type Resource struct {
	ID string `gorm:"column:id;primaryKey;default:generate_ulid()"`

	Provider string `gorm:"column:provider"`
	Scope    string `gorm:"column:scope"`
	UID      string `gorm:"column:uid"`

	Kind    string `gorm:"column:kind"`
	Type    string `gorm:"column:type"`
	Name    string `gorm:"column:name"`
	Service string `gorm:"column:service"`
	Region  string `gorm:"column:region"`

	AccountName string  `gorm:"column:account_name"`
	OrgUID      string  `gorm:"column:org_uid"`
	OrgName     string  `gorm:"column:org_name"`
	Engines     pq.StringArray `gorm:"column:engines;type:text[]"`
	TargetID    *string `gorm:"column:target_id"`

	ConfigType  string         `gorm:"column:config_type"`
	ExternalIDs pq.StringArray `gorm:"column:external_ids;type:text[]"`

	// Finding sync owns the catalog link, which is why ResourceFrom and the
	// engine upsert leave these fields untouched.
	ConfigID       *string `gorm:"column:config_id"`
	ConfigRolledUp bool    `gorm:"column:config_rolled_up"`

	ConfigMatchMethod string `gorm:"column:config_match_method"`
	ConfigServer      string `gorm:"column:config_server"`

	Tags     pq.StringArray          `gorm:"column:tags;type:text[]"`
	Labels   JSON[map[string]string] `gorm:"column:labels;type:jsonb"`
	Metadata JSON[map[string]any]    `gorm:"column:metadata;type:jsonb"`

	State       string    `gorm:"column:state"`
	FirstSeen   time.Time `gorm:"column:first_seen"`
	LastSeen    time.Time `gorm:"column:last_seen"`
	FirstScanID *string   `gorm:"column:first_scan_id"`
	LastScanID  *string   `gorm:"column:last_scan_id"`

	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (Resource) TableName() string { return "resources" }

// Document projects the row onto the wire type.
//
// The open-finding counts are passed in rather than stored on the row: they
// change with every later run and with a mute rule edit that never touches the
// resource at all, so a cached column would go quietly wrong. Scan.Document
// takes its counts the same way and for the same reason.
func (r Resource) Document(open int, severities map[string]int) api.Resource {
	return api.Resource{
		ID:          r.ID,
		Provider:    r.Provider,
		Scope:       r.Scope,
		UID:         r.UID,
		Kind:        r.Kind,
		Type:        r.Type,
		Name:        r.Name,
		Service:     r.Service,
		Region:      r.Region,
		TargetID:    deref(r.TargetID),
		AccountName: r.AccountName,
		OrgUID:      r.OrgUID,
		OrgName:     r.OrgName,
		Engines:     api.StringList(orEmpty(stringSlice(r.Engines))),
		ConfigType:  r.ConfigType,
		ExternalIDs: api.StringList(stringSlice(r.ExternalIDs)),
		ConfigID:    deref(r.ConfigID),
		Tags:        api.StringList(orEmpty(stringSlice(r.Tags))),
		Labels:      r.Labels.Get(),
		Metadata:    r.Metadata.Get(),
		State:       r.State,
		FirstSeen:   r.FirstSeen.Format(time.RFC3339),
		LastSeen:    r.LastSeen.Format(time.RFC3339),
		ScanID:      deref(r.LastScanID),
		Findings:    open,
		Severities:  severities,
	}
}

// ResourceFrom builds a row from what an engine reported.
//
// The engine is the run's, not the payload's. It is one value for every resource
// a run emits, so asking each engine to stamp it on every record was three
// copies of a constant and a field a new engine could forget.
//
// Every string is scrubbed of NUL for the reason FindingFrom is: metadata is the
// provider's own arbitrary document, Postgres accepts NUL in neither text nor
// jsonb, and one such byte would abort the insert for the whole run.
func ResourceFrom(scanID, engine string, seen time.Time, resource api.Resource) Resource {
	row := Resource{
		Provider:    scrub(resource.Provider),
		Scope:       scrub(resource.Scope),
		UID:         scrub(resource.UID),
		Kind:        scrub(resource.Kind),
		Type:        scrub(resource.Type),
		Name:        scrub(resource.Name),
		Service:     scrub(resource.Service),
		Region:      scrub(resource.Region),
		AccountName: scrub(resource.AccountName),
		OrgUID:      scrub(resource.OrgUID),
		OrgName:     scrub(resource.OrgName),
		Engines:     pq.StringArray(orEmpty(scrubAll([]string{engine}))),
		TargetID:    nonEmpty(scrub(resource.TargetID)),
		ConfigType:  scrub(resource.ConfigType),
		// Never nil: these columns are NOT NULL with a '{}' default, and gorm
		// sends an explicit NULL for a nil slice rather than letting the default
		// apply.
		ExternalIDs: pq.StringArray(orEmpty(scrubAll(resource.ExternalIDs))),
		Tags:        pq.StringArray(orEmpty(scrubAll(resource.Tags))),
		Labels:      wrapStringMap(scrubStringMap(resource.Labels)),
		Metadata:    wrapMap(scrubMap(resource.Metadata)),
		State:       api.ResourcePresent,
		FirstSeen:   seen,
		LastSeen:    seen,
		FirstScanID: nonEmpty(scanID),
		LastScanID:  nonEmpty(scanID),
	}
	if row.Kind == "" {
		row.Kind = api.KindCloudResource
	}
	return row
}

func scrubStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[scrub(key)] = scrub(value)
	}
	return out
}

func wrapStringMap(value map[string]string) JSON[map[string]string] {
	if value == nil {
		return JSON[map[string]string]{}
	}
	return Wrap(&value)
}
