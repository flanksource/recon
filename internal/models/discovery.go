package models

import (
	"time"

	"github.com/lib/pq"

	"github.com/flanksource/recon/internal/api"
)

// Discovery is one row of the discoveries table — one sweep.
type Discovery struct {
	ID    string `gorm:"column:id;primaryKey;default:generate_ulid()"`
	Chain string `gorm:"column:chain"`

	RanAt      time.Time `gorm:"column:ran_at"`
	Log        *string   `gorm:"column:log"`
	DurationMs int       `gorm:"column:duration_ms"`
	Failed     bool      `gorm:"column:failed"`
	Error      *string   `gorm:"column:error"`

	CreatedAt time.Time `gorm:"column:created_at;<-:create"`
}

// TableName is explicit; see Target.TableName.
func (Discovery) TableName() string { return "discoveries" }

// Document projects the row onto the wire type. Hosts are loaded separately so
// the runs list does not have to carry them.
func (d Discovery) Document(hosts []api.DiscoveredHost) api.Discover {
	unknown := 0
	for _, host := range hosts {
		if !host.Known {
			unknown++
		}
	}
	if hosts == nil {
		hosts = []api.DiscoveredHost{}
	}

	return api.Discover{
		ID:         d.ID,
		Chain:      d.Chain,
		RanAt:      d.RanAt.In(time.Local).Format("2006-01-02T15:04:05"),
		DurationMs: d.DurationMs,
		Failed:     d.Failed,
		Error:      deref(d.Error),
		Log:        deref(d.Log),
		Hosts:      hosts,
		Unknown:    unknown,
	}
}

// DiscoveryHost is one host a sweep observed, per engine that saw it.
type DiscoveryHost struct {
	DiscoveryID string `gorm:"column:discovery_id;primaryKey"`
	Host        string `gorm:"column:host;primaryKey"`
	Engine      string `gorm:"column:engine;primaryKey"`
	Live        bool   `gorm:"column:live"`

	Probe JSON[map[string]any] `gorm:"column:probe;type:jsonb"`
}

// TableName is explicit; see Target.TableName.
func (DiscoveryHost) TableName() string { return "discovery_hosts" }

// UnknownHost is a host seen by discovery that is not in the inventory.
type UnknownHost struct {
	Host      string    `gorm:"column:host;primaryKey"`
	FirstSeen time.Time `gorm:"column:first_seen"`
	LastSeen  time.Time `gorm:"column:last_seen"`

	Probe JSON[map[string]any] `gorm:"column:probe;type:jsonb"`
}

// TableName is explicit; see Target.TableName.
func (UnknownHost) TableName() string { return "discovery_unknown_hosts" }

// EngineProfile is one row of the engine_profiles table.
type EngineProfile struct {
	Kind   string `gorm:"column:kind;primaryKey"`
	Engine string `gorm:"column:engine;primaryKey"`
	Name   string `gorm:"column:name;primaryKey"`

	Config  JSON[map[string]any] `gorm:"column:config;type:jsonb"`
	Comment *string              `gorm:"column:comment"`
	Paths   pq.StringArray       `gorm:"column:paths;type:text[]"`

	CreatedAt time.Time `gorm:"column:created_at;<-:create"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName is explicit; see Target.TableName.
func (EngineProfile) TableName() string { return "engine_profiles" }

// Document projects the row onto the wire type.
func (p EngineProfile) Document() api.Profile {
	profile := api.Profile{
		Kind:    p.Kind,
		Engine:  p.Engine,
		Name:    p.Name,
		Config:  p.Config.Get(),
		Comment: deref(p.Comment),
		Paths:   stringSlice(p.Paths),
	}
	if profile.Config == nil {
		profile.Config = map[string]any{}
	}
	return profile
}

// ProfileFrom builds a row from a wire profile.
func ProfileFrom(profile api.Profile) EngineProfile {
	row := EngineProfile{
		Kind:    profile.Kind,
		Engine:  profile.Engine,
		Name:    profile.Name,
		Comment: nonEmpty(profile.Comment),
		Paths:   pq.StringArray(profile.Paths),
	}
	if profile.Config != nil {
		config := profile.Config
		row.Config = JSON[map[string]any]{V: &config}
	}
	return row
}
