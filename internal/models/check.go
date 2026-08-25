package models

import (
	"time"

	"github.com/lib/pq"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/ocsf"
)

// Check is one row of the checks table: what a check is, as opposed to what it
// found.
//
// Written by the upsert in internal/store/checks.go rather than by gorm, the
// same arrangement FindingState has and for the same reason — the statement
// reads the run's own findings and never round-trips them through Go.
type Check struct {
	Engine  string `gorm:"column:engine;primaryKey"`
	CheckID string `gorm:"column:check_id;primaryKey"`

	Name        string         `gorm:"column:name"`
	Severity    string         `gorm:"column:severity"`
	Type        *string        `gorm:"column:type"`
	Remediation *string        `gorm:"column:remediation"`
	Reference   pq.StringArray `gorm:"column:reference;type:text[]"`
	Tags        pq.StringArray `gorm:"column:tags;type:text[]"`

	FirstSeen time.Time `gorm:"column:first_seen"`
	LastSeen  time.Time `gorm:"column:last_seen"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName is explicit; see Scan.TableName.
func (Check) TableName() string { return "checks" }

// Finding renders the catalogue entry as the evidence-shaped document the API
// returns when there is no evidence left to show.
//
// Synthetic is set because the difference matters to a reader: this describes
// what the check is, not what any particular run observed. Before the catalogue
// existed this shape was invented inline with the lifecycle reason stuffed into
// the remediation field, which was indistinguishable in the response from a real
// finding that genuinely recommended "resource-absent".
func (c Check) Finding() api.Finding {
	finding := api.Finding{
		DetectionFinding: ocsf.DetectionFinding{
			ClassUID:    ocsf.ClassUID,
			CategoryUID: ocsf.CategoryUID,
			TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
			ActivityID:  ocsf.ActivityIDCreate,
			SeverityID:  api.SeverityID(api.Severity(c.Severity)),
			FindingInfo: &ocsf.FindingInfo{
				UID:   c.CheckID,
				Title: firstNonEmpty(c.Name, c.CheckID),
				Types: orEmpty(stringSlice(c.Tags)),
			},
			Metadata: &ocsf.Metadata{
				Version:   ocsf.Version,
				EventCode: c.CheckID,
				Product:   &ocsf.Product{Name: deref(c.Type), VendorName: api.Vendor},
			},
		},
		CheckID:   c.CheckID,
		Engine:    deref(c.Type),
		Tags:      orEmpty(stringSlice(c.Tags)),
		Synthetic: true,
	}
	if remediation := deref(c.Remediation); remediation != "" || len(c.Reference) > 0 {
		finding.Remediation = &ocsf.Remediation{
			Desc:       remediation,
			References: stringSlice(c.Reference),
		}
	}
	return finding
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
