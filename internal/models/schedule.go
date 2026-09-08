package models

import (
	"time"

	"github.com/flanksource/recon/internal/api"
	"gorm.io/gorm"
)

// ScanSchedule stores configuration separately from the scans it creates.
type ScanSchedule struct {
	ID        string `gorm:"default:generate_ulid();<-:create"`
	Name      string `gorm:"primaryKey"`
	Enabled   bool
	Engine    string
	Profile   string
	Targets   JSON[map[string]any]
	Cron      string
	Timezone  string
	Confirm   bool
	NextRun   *time.Time
	LastRun   *time.Time
	LastError string
	CreatedAt time.Time `gorm:"<-:create"`
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt
}

// TableName matches the declarative migration.
func (ScanSchedule) TableName() string { return "scan_schedules" }

// Document exposes schedule configuration, execution state and server-owned timestamps.
func (s ScanSchedule) Document() api.ScanSchedule {
	return api.ScanSchedule{
		ID: s.ID, Name: s.Name, Enabled: s.Enabled, Engine: s.Engine, Profile: s.Profile,
		Targets: s.Targets.Get(), Cron: s.Cron, Timezone: s.Timezone, Confirm: s.Confirm,
		NextRun: s.NextRun, LastRun: s.LastRun, LastError: s.LastError,
		CreatedAt: s.CreatedAt, UpdatedAt: s.UpdatedAt,
	}
}
