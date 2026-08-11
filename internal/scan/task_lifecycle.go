package scan

import (
	"context"
	"fmt"
	"math"
	"sync/atomic"

	clickyexec "github.com/flanksource/clicky/exec"
	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/api"
)

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

type scanTaskDetails struct {
	clickyexec.ExecTaskDetails
	ScanID        string         `json:"scanId"`
	Engine        string         `json:"engine"`
	Profile       string         `json:"profile"`
	Phase         api.Phase      `json:"phase"`
	DurationMS    int64          `json:"durationMs"`
	EndpointCount int            `json:"endpointCount"`
	Findings      int            `json:"findings"`
	Severities    map[string]int `json:"severities"`
	Stats         *api.ScanStats `json:"stats,omitempty"`
}

type scanTaskBinding struct {
	Session  *session
	Snapshot func() api.Scan
}

func bindScanTask(scanTask *task.Task, binding scanTaskBinding) {
	if scanTask == nil || binding.Session == nil || binding.Snapshot == nil {
		panic("scan task, session, and snapshot are required")
	}
	scanTask.SetOutputProvider(binding.Session.OutputSnapshot)
	scanTask.SetDetailsProvider(func() any {
		scan := binding.Snapshot()
		return scanTaskDetails{
			ExecTaskDetails: binding.Session.TaskDetails(),
			ScanID:          scan.ID, Engine: scan.Engine, Profile: scan.Profile, Phase: scan.Phase,
			DurationMS: scan.DurationMS, EndpointCount: scan.EndpointCount,
			Findings: scan.Findings, Severities: scan.Severities, Stats: scan.Stats,
		}
	})
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
