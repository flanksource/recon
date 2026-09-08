package entities

import (
	"context"
	"sync"
	"time"

	"github.com/flanksource/clicky"
	"github.com/flanksource/commons/logger"
	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/scan"
	"github.com/flanksource/recon/internal/store"
)

// registerSchedule shares the configuration CRUD contract with mutes and profiles.
func (r *Registry) registerSchedule() {
	clicky.NewEntity[api.ScanSchedule, store.ScheduleOpts, api.ScanSchedule]("schedule").
		Aliases("schedules").ToolGroup("configuration").
		ListWithContext(bind(r, (*store.Store).ListSchedules)).
		GetWithContext(bind(r, (*store.Store).GetSchedule)).
		CreateWithContext(bind(r, createSchedule)).
		UpdateWithContext(bind2(r, updateSchedule)).
		DeleteWithContext(func(ctx context.Context, name string) error {
			st, err := r.store()
			if err != nil {
				return err
			}
			return st.DeleteSchedule(ctx, name)
		}).Register()
}

func createSchedule(st *store.Store, ctx context.Context, body map[string]any) (api.ScanSchedule, error) {
	body, err := requestBody(ctx, body)
	if err != nil {
		return api.ScanSchedule{}, err
	}
	schedule, err := api.ScanScheduleFrom(body)
	if err != nil {
		return api.ScanSchedule{}, err
	}
	return st.CreateSchedule(ctx, schedule)
}

func updateSchedule(st *store.Store, ctx context.Context, name string, body map[string]any) (api.ScanSchedule, error) {
	body, err := requestBody(ctx, body)
	if err != nil {
		return api.ScanSchedule{}, err
	}
	delete(body, "id")
	delete(body, "name")
	schedule, err := api.ScanScheduleFrom(body)
	if err != nil {
		return api.ScanSchedule{}, err
	}
	schedule.Name = name
	return st.UpdateSchedule(ctx, schedule)
}

// RunSchedules polls durable due times. Per-process admission avoids piling up
// goroutines, while the store's advisory locks coordinate other server processes.
// Cancellation stops polling and joins workers before the database is closed.
func (r *Registry) RunSchedules(ctx context.Context) {
	db, err := r.st.DB(ctx).DB()
	if err != nil {
		logger.Errorf("start scan schedules: %v", err)
		return
	}
	// Advisory locks pin sessions; reserve the other half of the pool for
	// scan persistence and UI requests rather than letting queued jobs starve them.
	capacity := db.Stats().MaxOpenConnections / 2
	if capacity == 0 {
		capacity = 1
	}
	slots := make(chan struct{}, capacity)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	var active sync.Map
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			names, err := r.st.DueSchedules(ctx)
			if err != nil {
				logger.Errorf("poll scan schedules: %v", err)
				continue
			}
			for _, name := range names {
				if _, busy := active.LoadOrStore(name, true); busy {
					continue
				}
				select {
				case slots <- struct{}{}:
				default:
					active.Delete(name)
					continue
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer func() { <-slots }()
					defer active.Delete(name)
					err := r.st.RunDueSchedule(ctx, name, func(schedule api.ScanSchedule) (api.Scan, error) {
						selector, err := api.ParseTargetSelector(schedule.Targets)
						if err != nil {
							return api.Scan{}, err
						}
						started, err := r.startScan(ctx, scanFlags{
							Engine: schedule.Engine, Profile: schedule.Profile, Confirm: schedule.Confirm,
						}, resolvedTarget{Inventory: selector}, scan.Creator{
							ScheduleID: schedule.ID,
						})
						if err != nil {
							return started, err
						}
						finished, err := r.Runtimes.Scans.Wait(ctx, started.ID)
						if ctx.Err() != nil {
							// Keep the database lock until the accepted run has stopped.
							_ = r.Runtimes.Scans.CancelID(started.ID)
							return r.Runtimes.Scans.Wait(context.WithoutCancel(ctx), started.ID)
						}
						return finished, err
					})
					if err != nil {
						logger.Errorf("scan schedule %q: %v", name, err)
					}
				}()
			}
		}
	}
}
