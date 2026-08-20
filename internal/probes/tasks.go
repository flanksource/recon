package probes

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/api"
)

// hostTaskController lets the task tree stop one host's probe. Copied in shape
// from discovery's stageTaskController: a task that has already finished offers
// no actions, which is what removes the Stop button from the UI.
type hostTaskController struct {
	task *task.Task
}

func (c hostTaskController) Actions() []task.ControlAction {
	if c.task.Status() == task.StatusPending || c.task.Status() == task.StatusRunning {
		return []task.ControlAction{task.ControlStop}
	}
	return nil
}

func (c hostTaskController) Control(_ context.Context, action task.ControlAction) error {
	if action != task.ControlStop {
		return fmt.Errorf("probe task does not support %q", action)
	}
	c.task.Cancel()
	return nil
}

// newTaskGroup starts the run's task group.
//
// The group id is the probes row id, so /api/v1/tasks/{id} and
// /api/v1/probe/{id} address the same run — which is what lets the browser
// follow a sweep and then read its record without being told two ids.
//
// WORKAROUND(clicky-worker-pool): the global task manager starts four workers
// at construction and never grows them, so a concurrency above four is recorded
// on the run but not honoured — the sweep is gated by the worker pool, not by
// this group's semaphore.
// Correct fix: resize the global task worker pool when max concurrency changes.
// Ref: gavel todo c7f7cd43-1a44-4127-8de9-105efb07304a
//
// Deliberately not clicky.SetGlobalMaxConcurrency, which `reconctl ping` does
// call: that resizes the process-global semaphore, and doing it from inside an
// HTTP request would silently re-gate concurrent scans and discovery sweeps.
func newTaskGroup(id, label string, total int, concurrency int) task.TypedGroup[api.ProbeResult] {
	return clicky.StartGroup[api.ProbeResult]("probe "+label,
		task.WithGroupID(id),
		task.WithKind("probe"),
		task.WithLabels(map[string]string{
			"hosts":    strconv.Itoa(total),
			"selector": label,
		}),
		// No page addresses a probe run on its own; the inventory it refreshed is
		// the useful destination.
		task.WithHref("/inventory"),
		task.WithConcurrency(concurrency),
	)
}

// taskOptions are the per-host options every probe task carries.
//
// Retries are disabled explicitly. Clicky's default retries three times on
// errors whose text contains "timeout" or "connection" — which is exactly what
// a host that is down produces, so inheriting the default would probe every
// dead host four times and spend the sweep's slowest minutes re-confirming what
// it already knew.
//
// The task timeout covers both legs of a host, because a bare host is tried
// over HTTPS and then HTTP.
func taskOptions(timeout time.Duration) []task.Option {
	return []task.Option{
		task.WithTaskTimeout(2*timeout + timeout/2),
		task.WithRetryConfig(task.RetryConfig{}),
	}
}

// describe renders the one-line summary the task tree shows for a host.
//
// The kind leads the message, matching `reconctl ping`: a tree of wrapped dial
// errors is a wall of text where the one word that says which team owns the
// problem is buried at the end.
func describe(result api.ProbeResult) string {
	if result.Up {
		return fmt.Sprintf("%d in %dms", result.StatusCode, result.ResponseTimeMs)
	}
	switch {
	case result.Failure != "" && result.Error != "":
		return fmt.Sprintf("%s: %s", result.Failure, result.Error)
	case result.Failure != "":
		return string(result.Failure)
	case result.Error != "":
		return result.Error
	}
	return "no answer"
}
