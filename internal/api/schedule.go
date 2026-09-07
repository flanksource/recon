package api

import (
	"fmt"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// ScanSchedule is durable scan configuration; execution fields are server-owned.
type ScanSchedule struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Engine    string         `json:"engine"`
	Profile   string         `json:"profile"`
	Targets   map[string]any `json:"targets"`
	Cron      string         `json:"cron"`
	Timezone  string         `json:"timezone"`
	Confirm   bool           `json:"confirm"`
	NextRun   *time.Time     `json:"nextRun,omitempty"`
	LastRun   *time.Time     `json:"lastRun,omitempty"`
	LastError string         `json:"lastError,omitempty"`
}

// GetID keeps entity addresses stable when schedules are edited.
func (s ScanSchedule) GetID() string { return s.Name }

// GetName is the human-readable entity label.
func (s ScanSchedule) GetName() string { return s.Name }

// Frequency validates a calendar in its explicit timezone, independent of the server's locale.
func (s ScanSchedule) Frequency() (cron.Schedule, error) {
	if _, err := time.LoadLocation(s.Timezone); err != nil || s.Timezone == "" || s.Timezone == "Local" {
		return nil, fmt.Errorf("timezone must be an IANA timezone such as UTC or Asia/Katmandu")
	}
	if strings.Contains(s.Cron, "TZ=") {
		return nil, fmt.Errorf("use the timezone field rather than a timezone prefix in cron")
	}
	if interval, ok := strings.CutPrefix(strings.TrimSpace(s.Cron), "@every "); ok {
		duration, err := time.ParseDuration(strings.TrimSpace(interval))
		if err != nil || duration < time.Second {
			return nil, fmt.Errorf("@every interval must be at least one second")
		}
	}
	frequency, err := cron.ParseStandard("CRON_TZ=" + s.Timezone + " " + s.Cron)
	if err != nil {
		return nil, err
	}
	if frequency.Next(time.Now()).IsZero() {
		return nil, fmt.Errorf("cron has no next firing")
	}
	return frequency, nil
}

// ScanScheduleFrom accepts only editable fields, not execution state supplied by a client.
func ScanScheduleFrom(body map[string]any) (ScanSchedule, error) {
	for _, key := range []string{"id", "nextRun", "lastRun", "lastError"} {
		if _, ok := body[key]; ok {
			return ScanSchedule{}, fmt.Errorf("%s is read-only", key)
		}
	}
	if value, ok := body["targets"]; ok {
		targets, err := objectFrom(value, "targets")
		if err != nil {
			return ScanSchedule{}, err
		}
		body["targets"] = targets
	}
	schedule := ScanSchedule{Timezone: "UTC", Enabled: true}
	if err := decode(body, &schedule); err != nil {
		return ScanSchedule{}, err
	}
	return schedule, nil
}
