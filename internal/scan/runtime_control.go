package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/store"
)

// Wait blocks until the current run finishes and returns how it ended.
//
// The CLI needs this: a scan runs in a goroutine, so a command that returned as
// soon as the engine started would exit and take the run with it, leaving the
// row stuck at "running" forever. The server does not wait — that is what the
// event stream is for.
func (r *Runtime) Wait(ctx context.Context, id string) (api.Scan, error) {
	r.mu.Lock()
	run := r.runs[id]
	r.mu.Unlock()

	if run == nil {
		return api.Scan{}, fmt.Errorf("scan %q is not active in this runtime", id)
	}

	select {
	case <-run.done:
	case <-ctx.Done():
		return api.Scan{}, ctx.Err()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	return run.Scan, nil
}

// Cancel stops the running scan and everything it started.
func (r *Runtime) Cancel() error {
	r.mu.Lock()
	run := r.current
	r.mu.Unlock()

	if run == nil || run.Scan.Phase.Terminal() {
		return fmt.Errorf("no scan is running")
	}
	return r.cancelRun(run)
}

func (r *Runtime) cancelRun(run *Run) error {
	r.mu.Lock()
	if run.Scan.Phase.Terminal() {
		r.mu.Unlock()
		return fmt.Errorf("scan %s is not running or queued", run.Scan.Name)
	}

	queued := run.Scan.Phase == api.PhaseQueued
	if queued {
		finished := time.Now()
		run.Scan.Phase = api.PhaseCancelled
		run.Scan.FinishedAt = finished.Format("2006-01-02T15:04:05")
		run.Scan.OutputCaptured = true
		run.row.Phase = string(api.PhaseCancelled)
		run.row.FinishedAt = &finished
		run.row.DurationMS = 0
	}
	scanTask := run.task
	current := run.session
	if scanTask != nil {
		scanTask.Cancel()
	}
	if queued {
		run.queueDone()
		if err := r.Store.FinalizeScan(context.Background(), store.FinalizeScanOptions{
			Scan: run.row, Output: models.ScanOutput{},
		}); err != nil {
			run.Scan.Phase = api.PhaseFailed
			run.Scan.Error = fmt.Sprintf("persist queued cancellation: %v", err)
			run.doneOnce.Do(func() { close(run.done) })
			r.publish()
			r.mu.Unlock()
			return err
		}
		run.doneOnce.Do(func() { close(run.done) })
		r.publish()
	}
	r.mu.Unlock()

	if queued {
		current.Cleanup()
		return nil
	}
	return current.Cancel()
}
