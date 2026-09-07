package store

import (
	"context"
	"database/sql/driver"
	"fmt"
	"regexp"
	"time"

	"github.com/flanksource/recon/internal/api"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/models"
)

// ScheduleOpts keeps the schedule listing on the entity CRUD surface.
type ScheduleOpts struct{}

// ListSchedules includes disabled schedules so they can be edited and re-enabled.
func (s *Store) ListSchedules(ctx context.Context, _ ScheduleOpts) ([]api.ScanSchedule, error) {
	var rows []models.ScanSchedule
	if err := s.DB(ctx).Order("name").Find(&rows).Error; err != nil {
		return nil, err
	}
	result := make([]api.ScanSchedule, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.Document())
	}
	return result, nil
}

// GetSchedule reads one durable schedule by its stable name.
func (s *Store) GetSchedule(ctx context.Context, name string) (api.ScanSchedule, error) {
	var row models.ScanSchedule
	if err := s.DB(ctx).Where("name = ?", name).First(&row).Error; err != nil {
		if IsNotFound(err) {
			return api.ScanSchedule{}, NotFound("schedule", name)
		}
		return api.ScanSchedule{}, err
	}
	return row.Document(), nil
}

var scheduleName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func (s *Store) scheduleRow(ctx context.Context, input api.ScanSchedule) (models.ScanSchedule, error) {
	row := models.ScanSchedule{
		Name: input.Name, Enabled: input.Enabled, Engine: input.Engine, Profile: input.Profile,
		Targets: models.Wrap(&input.Targets), Cron: input.Cron, Timezone: input.Timezone, Confirm: input.Confirm,
	}
	if !scheduleName.MatchString(input.Name) {
		return row, fmt.Errorf("name must use lowercase letters, digits and dashes, starting with a letter or digit")
	}
	if input.Targets == nil {
		return row, fmt.Errorf("targets is required; use {} explicitly for the whole inventory")
	}
	if _, err := api.ParseTargetSelector(input.Targets); err != nil {
		return row, err
	}
	engine, err := enginescan.Get(input.Engine)
	if err != nil {
		return row, err
	}
	profile, err := s.GetProfile(ctx, "scan:"+input.Engine+":"+input.Profile)
	if err != nil {
		return row, err
	}
	if err := engine.Spec().ValidateConfig(profile.Config); err != nil {
		return row, err
	}
	frequency, err := input.Frequency()
	if err != nil {
		return row, err
	}
	if input.Enabled {
		next := frequency.Next(time.Now())
		row.NextRun = &next
	}
	return row, nil
}

// CreateSchedule inserts rather than upserts, so a duplicate cannot replace another schedule.
func (s *Store) CreateSchedule(ctx context.Context, input api.ScanSchedule) (api.ScanSchedule, error) {
	row, err := s.scheduleRow(ctx, input)
	if err != nil {
		return api.ScanSchedule{}, err
	}
	if err := s.DB(ctx).Create(&row).Error; err != nil {
		return api.ScanSchedule{}, err
	}
	return s.GetSchedule(ctx, row.Name)
}

// UpdateSchedule replaces configuration and recalculates the next firing without changing history.
func (s *Store) UpdateSchedule(ctx context.Context, input api.ScanSchedule) (api.ScanSchedule, error) {
	row, err := s.scheduleRow(ctx, input)
	if err != nil {
		return api.ScanSchedule{}, err
	}
	result := s.DB(ctx).Model(&models.ScanSchedule{}).Where("name = ?", row.Name).Updates(map[string]any{
		"enabled": row.Enabled, "engine": row.Engine, "profile": row.Profile,
		"targets": row.Targets, "cron": row.Cron, "timezone": row.Timezone, "confirm": row.Confirm,
		"next_run": row.NextRun, "updated_at": time.Now(),
	})
	if result.Error != nil {
		return api.ScanSchedule{}, result.Error
	}
	if result.RowsAffected == 0 {
		return api.ScanSchedule{}, NotFound("schedule", row.Name)
	}
	return s.GetSchedule(ctx, row.Name)
}

// DeleteSchedule prevents future firings; already accepted scans keep their own lifecycle.
func (s *Store) DeleteSchedule(ctx context.Context, name string) error {
	result := s.DB(ctx).Where("name = ?", name).Delete(&models.ScanSchedule{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return NotFound("schedule", name)
	}
	return nil
}

// DueSchedules is polled by servers; claiming is separate so polling never blocks on a scan.
func (s *Store) DueSchedules(ctx context.Context) ([]string, error) {
	var names []string
	err := s.DB(ctx).Model(&models.ScanSchedule{}).Where("enabled AND next_run <= ?", time.Now()).Order("next_run, name").Pluck("name", &names).Error
	return names, err
}

// RunDueSchedule holds a session advisory lock across discovery, queueing and execution.
// The lock coordinates servers and is released on connection loss; no long-lived
// transaction prevents UI edits. A compare-and-swap claim serializes edits with admission.
func (s *Store) RunDueSchedule(ctx context.Context, name string, run func(api.ScanSchedule) (api.Scan, error)) error {
	db, err := s.DB(ctx).DB()
	if err != nil {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	key := "recon:scan-schedule:" + name
	var locked bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1, 0))", key).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(cleanup, "SELECT pg_advisory_unlock(hashtextextended($1, 0))", key); err != nil {
			// Never return a possibly locked session to the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	var row models.ScanSchedule
	err = s.DB(ctx).Where("name = ?", name).First(&row).Error
	if IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	schedule := row.Document()
	if !schedule.Enabled || schedule.NextRun == nil || schedule.NextRun.After(time.Now()) {
		return nil
	}
	frequency, err := schedule.Frequency()
	if err != nil {
		return err
	}
	now := time.Now().Truncate(time.Microsecond)
	next := frequency.Next(now)
	claim := s.DB(ctx).Model(&models.ScanSchedule{}).
		Where("id = ? AND enabled AND next_run = ? AND updated_at = ?", schedule.ID, schedule.NextRun, row.UpdatedAt).
		UpdateColumns(map[string]any{"next_run": next, "last_run": now, "last_error": ""})
	if claim.Error != nil || claim.RowsAffected == 0 {
		return claim.Error
	}
	result, runErr := run(schedule)
	message := result.Error
	if runErr != nil {
		message = runErr.Error()
	}
	finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.DB(finish).Model(&models.ScanSchedule{}).Where("id = ? AND last_run = ?", schedule.ID, now).
		UpdateColumn("last_error", message).Error; err != nil {
		return err
	}
	// Skip firings missed while busy, but never overwrite a concurrent edit's next firing.
	return s.DB(finish).Model(&models.ScanSchedule{}).
		Where("id = ? AND enabled AND next_run = ? AND updated_at = ? AND last_run = ?", schedule.ID, next, row.UpdatedAt, now).
		UpdateColumn("next_run", frequency.Next(time.Now())).Error
}
