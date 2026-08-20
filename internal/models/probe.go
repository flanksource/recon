package models

import (
	"time"

	"github.com/flanksource/recon/internal/api"
)

// Probe is one row of the probes table — one liveness sweep.
type Probe struct {
	ID string `gorm:"column:id;primaryKey;default:generate_ulid()"`

	Selector JSON[map[string]any] `gorm:"column:selector;type:jsonb"`
	Total    int                  `gorm:"column:total"`

	TimeoutMS       int  `gorm:"column:timeout_ms"`
	Concurrency     int  `gorm:"column:concurrency"`
	FollowRedirects bool `gorm:"column:follow_redirects"`

	Phase      string     `gorm:"column:phase"`
	RanAt      time.Time  `gorm:"column:ran_at"`
	FinishedAt *time.Time `gorm:"column:finished_at"`
	DurationMS int        `gorm:"column:duration_ms"`
	Error      *string    `gorm:"column:error"`

	CreatedAt time.Time `gorm:"column:created_at;<-:create"`
}

// TableName is explicit so a gorm naming-strategy change cannot repoint the
// model at a different table than the HCL declares.
func (Probe) TableName() string { return "probes" }

// ProbeCounts are the aggregates derived from the run's results.
//
// Derived rather than stored: a counter on the row would need writing every
// time a host finished, and would need a second code path for a run that is
// still going. One source of truth, counted where the rows are.
type ProbeCounts struct {
	Live    int
	Updated int
}

// Document projects the row onto the wire type.
//
// Timestamps are formatted without a zone, matching Scan.Document: the frontend
// sorts these as strings, so emitting an offset here would reorder the list.
func (p Probe) Document(results []api.ProbeResult, counts ProbeCounts, label string) api.ProbeRun {
	run := api.ProbeRun{
		ID:            p.ID,
		Selector:      p.Selector.Get(),
		SelectorLabel: label,
		Phase:         api.Phase(p.Phase),
		RanAt:         localTimestamp(p.RanAt),
		DurationMs:    p.DurationMS,
		Total:         p.Total,
		Live:          counts.Live,
		Updated:       counts.Updated,
		Error:         deref(p.Error),
		Results:       results,
	}
	if p.FinishedAt != nil {
		run.FinishedAt = localTimestamp(*p.FinishedAt)
	}
	if run.Selector == nil {
		run.Selector = map[string]any{}
	}
	if run.Results == nil {
		run.Results = []api.ProbeResult{}
	}
	return run
}

// ProbeResult is one row of the probe_results table — what one host answered.
type ProbeResult struct {
	ProbeID string `gorm:"column:probe_id;primaryKey"`
	Host    string `gorm:"column:host;primaryKey"`

	URL            *string   `gorm:"column:url"`
	Up             bool      `gorm:"column:up"`
	StatusCode     *int      `gorm:"column:status_code"`
	ResponseTimeMS int64     `gorm:"column:response_time_ms"`
	IP             *string   `gorm:"column:ip"`
	ContentType    *string   `gorm:"column:content_type"`
	Error          *string   `gorm:"column:error"`
	Failure        *string   `gorm:"column:failure"`
	Updated        bool      `gorm:"column:updated"`
	ProbedAt       time.Time `gorm:"column:probed_at"`
}

// TableName is explicit; see Probe.TableName.
func (ProbeResult) TableName() string { return "probe_results" }

// Document projects the row onto the wire type.
func (r ProbeResult) Document() api.ProbeResult {
	result := api.ProbeResult{
		Host:           r.Host,
		URL:            deref(r.URL),
		Up:             r.Up,
		ResponseTimeMs: r.ResponseTimeMS,
		IP:             deref(r.IP),
		ContentType:    deref(r.ContentType),
		Error:          deref(r.Error),
		Failure:        api.Failure(deref(r.Failure)),
		Updated:        r.Updated,
		ProbedAt:       r.ProbedAt.In(time.Local).Format("2006-01-02T15:04:05"),
	}
	if r.StatusCode != nil {
		result.StatusCode = *r.StatusCode
	}
	return result
}

// ProbeResultFrom builds a row from what a probe saw.
func ProbeResultFrom(probeID string, result api.ProbeResult, probedAt time.Time) ProbeResult {
	row := ProbeResult{
		ProbeID:        probeID,
		Host:           scrub(result.Host),
		URL:            nonEmpty(scrub(result.URL)),
		Up:             result.Up,
		ResponseTimeMS: result.ResponseTimeMs,
		IP:             nonEmpty(scrub(result.IP)),
		ContentType:    nonEmpty(scrub(result.ContentType)),
		Error:          nonEmpty(scrub(result.Error)),
		Failure:        nonEmpty(string(result.Failure)),
		Updated:        result.Updated,
		ProbedAt:       probedAt,
	}
	if result.StatusCode > 0 {
		status := result.StatusCode
		row.StatusCode = &status
	}
	return row
}
