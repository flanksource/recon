package models

import (
	"time"

	"github.com/lib/pq"

	"github.com/flanksource/recon/internal/api"
)

// MuteRule is one row of the mute_rules table.
type MuteRule struct {
	Name     string  `gorm:"column:name;primaryKey"`
	Comment  *string `gorm:"column:comment"`
	Disabled bool    `gorm:"column:disabled"`

	Engines pq.StringArray `gorm:"column:engines;type:text[]"`

	Targets JSON[map[string]any] `gorm:"column:targets;type:jsonb"`

	Resources pq.StringArray `gorm:"column:resources;type:text[]"`
	Templates pq.StringArray `gorm:"column:templates;type:text[]"`
	Tags      pq.StringArray `gorm:"column:tags;type:text[]"`
	Severity  pq.StringArray `gorm:"column:severity;type:text[]"`

	Expr *string `gorm:"column:expr"`

	CreatedAt time.Time `gorm:"column:created_at;<-:create"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName is explicit; see Scan.TableName.
func (MuteRule) TableName() string { return "mute_rules" }

// Document projects the row onto the wire type.
func (m MuteRule) Document() api.MuteRule {
	rule := api.MuteRule{
		Name:      m.Name,
		Comment:   deref(m.Comment),
		Disabled:  m.Disabled,
		Engines:   api.StringList(stringSlice(m.Engines)),
		Targets:   m.Targets.Get(),
		Resources: api.StringList(stringSlice(m.Resources)),
		Templates: api.StringList(stringSlice(m.Templates)),
		Tags:      api.StringList(stringSlice(m.Tags)),
		Severity:  api.StringList(stringSlice(m.Severity)),
		Expr:      deref(m.Expr),
		CreatedAt: m.CreatedAt.Format(time.RFC3339),
		UpdatedAt: m.UpdatedAt.Format(time.RFC3339),
	}
	if rule.Targets == nil {
		rule.Targets = map[string]any{}
	}
	return rule
}

// MuteRuleFrom builds a row from a validated rule.
//
// Every list is stored as an empty array rather than NULL: the columns are NOT
// NULL with a '{}' default, and GORM sends an explicit NULL for a nil slice
// rather than letting the default apply — the same trap FindingFrom documents.
func MuteRuleFrom(rule api.MuteRule) MuteRule {
	// The column is NOT NULL with a '{}' default, and a nil map would be sent as
	// an explicit NULL rather than letting the default apply. An unconstrained
	// target scope is an empty selector, not an absent one.
	targets := rule.Targets
	if targets == nil {
		targets = map[string]any{}
	}
	return MuteRule{
		Name:      rule.Name,
		Comment:   nonEmpty(rule.Comment),
		Disabled:  rule.Disabled,
		Engines:   pq.StringArray(orEmpty(rule.Engines)),
		Targets:   wrapMap(targets),
		Resources: pq.StringArray(orEmpty(rule.Resources)),
		Templates: pq.StringArray(orEmpty(rule.Templates)),
		Tags:      pq.StringArray(orEmpty(rule.Tags)),
		Severity:  pq.StringArray(orEmpty(rule.Severity)),
		Expr:      nonEmpty(rule.Expr),
	}
}
