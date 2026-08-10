package scan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"

	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
)

type managedScan struct {
	*task.ManagedRun
	controller *scanTaskController
}

type scanTaskController struct {
	stop     func() error
	stopping atomic.Bool
	task     atomic.Pointer[task.Task]
}

func (c *scanTaskController) Actions() []task.ControlAction {
	if c.stopping.Load() {
		return nil
	}
	if t := c.task.Load(); t != nil && t.Status() != task.StatusPending && t.Status() != task.StatusRunning {
		return nil
	}
	return []task.ControlAction{task.ControlStop}
}

func (c *scanTaskController) Control(_ context.Context, action task.ControlAction) error {
	if action != task.ControlStop {
		return fmt.Errorf("scan task does not support %q", action)
	}
	if !c.stopping.CompareAndSwap(false, true) {
		return fmt.Errorf("scan task is already stopping")
	}
	return c.stop()
}

func startManagedScan(name, engine, profile string, stop func() error) *managedScan {
	if stop == nil {
		panic("scan task stop function is required")
	}
	controller := &scanTaskController{stop: stop}
	managed := task.StartManagedRun(name,
		task.WithKind("scan"),
		task.WithLabels(map[string]string{"engine": engine, "profile": profile}),
		task.WithController(controller),
	)
	controller.task.Store(managed.Task())
	return &managedScan{ManagedRun: managed, controller: controller}
}

func bindManagedScan(run *managedScan, invocation *engines.Invocation) {
	if run == nil || invocation == nil {
		panic("scan task and invocation are required")
	}
	run.SetOutputProvider(invocation.OutputSnapshot)
	run.SetDetailsProvider(func() any { return invocation.TaskDetails() })
}

func updateTaskProgress(t *task.Task, stats *api.ScanStats) {
	if t == nil || stats == nil {
		return
	}
	if stats.Total > 0 {
		requests, requestsOK := taskProgressValue(stats.Requests)
		total, totalOK := taskProgressValue(stats.Total)
		if requestsOK && totalOK && total > 0 {
			t.SetProgress(min(requests, total), total)
		}
	} else if percent, ok := taskProgressValue(stats.Percent); ok && percent > 0 && percent <= 100 {
		t.SetProgress(percent, 100)
	}
}

func taskProgressValue(value float64) (int, bool) {
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) || value >= float64(^uint(0)>>1) {
		return 0, false
	}
	return int(math.Round(value)), true
}

func finishManagedScan(run *managedScan, phase api.Phase, problem string) {
	if run == nil {
		panic("scan task run is required")
	}
	run.controller.stopping.Store(true)

	status := task.StatusSuccess
	switch phase {
	case api.PhaseDone:
		if problem != "" {
			status = task.StatusWarning
		}
	case api.PhaseFailed:
		status = task.StatusFailed
	case api.PhaseCancelled:
		status = task.StatusCancelled
	default:
		panic("cannot finish scan task in phase " + phase)
	}

	var err error
	if problem != "" {
		err = errors.New(problem)
	}
	run.Finish(status, err)
}
