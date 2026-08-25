package models

import (
	"time"

	"github.com/flanksource/recon/internal/api"
)

// FindingState is what is currently true about one check on one resource.
//
// The findings table is per-run evidence: two runs of the same profile write
// two complete copies and nothing in them says which of the first run's
// findings the second one fixed. This row is where that difference lives, and
// it is written entirely by the reconciliation statements in
// internal/store/finding_states.go rather than by gorm — the struct exists so
// the API and the tests have something typed to read back.
type FindingState struct {
	ID         string `gorm:"column:id;primaryKey;default:generate_ulid()"`
	ResourceID string `gorm:"column:resource_id"`
	Engine     string `gorm:"column:engine"`
	CheckID    string `gorm:"column:check_id"`

	Status   string  `gorm:"column:status"`
	Severity string  `gorm:"column:severity"`
	Reason   *string `gorm:"column:reason"`

	FirstSeen  time.Time  `gorm:"column:first_seen"`
	LastSeen   time.Time  `gorm:"column:last_seen"`
	LastOpenAt *time.Time `gorm:"column:last_open_at"`
	ResolvedAt *time.Time `gorm:"column:resolved_at"`

	FirstScanID *string `gorm:"column:first_scan_id"`
	LastScanID  string  `gorm:"column:last_scan_id"`
	OpenScanID  *string `gorm:"column:open_scan_id"`
	FindingID   *string `gorm:"column:finding_id"`

	MutedBy     *string `gorm:"column:muted_by"`
	Occurrences int     `gorm:"column:occurrences"`
	TargetID    *string `gorm:"column:target_id"`

	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName is explicit; see Scan.TableName.
func (FindingState) TableName() string { return "finding_states" }

// Document projects the row onto the wire type.
func (s FindingState) Document() api.FindingState {
	state := api.FindingState{
		ID:          s.ID,
		ResourceID:  s.ResourceID,
		Engine:      s.Engine,
		CheckID:     s.CheckID,
		Status:      s.Status,
		Severity:    s.Severity,
		Reason:      deref(s.Reason),
		FirstSeen:   localTimestamp(s.FirstSeen),
		LastSeen:    localTimestamp(s.LastSeen),
		FirstScanID: deref(s.FirstScanID),
		LastScanID:  s.LastScanID,
		OpenScanID:  deref(s.OpenScanID),
		FindingID:   deref(s.FindingID),
		MutedBy:     deref(s.MutedBy),
		Occurrences: s.Occurrences,
		TargetID:    deref(s.TargetID),
	}
	if s.LastOpenAt != nil {
		state.LastOpenAt = localTimestamp(*s.LastOpenAt)
	}
	if s.ResolvedAt != nil {
		state.ResolvedAt = localTimestamp(*s.ResolvedAt)
	}
	return state
}
