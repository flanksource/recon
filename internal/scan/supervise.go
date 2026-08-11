package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/store"
)

// supervise runs the engine, then records what it found.
func (r *Runtime) supervise(
	ctx context.Context,
	scanTask *task.Task,
	run *Run,
	engine enginescan.Engine,
	row models.Scan,
	engineRun engines.Run,
) {
	defer run.doneOnce.Do(func() { close(run.done) })
	defer run.session.Cleanup()

	timer := time.AfterFunc(maxDuration, func() {
		run.Output.Append(StreamSystem,
			fmt.Sprintf("[!] scan exceeded %s and was cancelled\n", maxDuration))
		_ = r.cancelRun(run)
	})
	defer timer.Stop()

	// The task's progress bar is driven from the same stats the UI reads, on a
	// ticker rather than per-callback: nuclei reports every request, and
	// repainting the task tree thousands of times a second is not progress.
	stopProgress := r.trackProgress(scanTask, run)

	runErr := run.session.Run(ctx, engine, engineRun)
	stopProgress()
	run.Output.Flush()

	findings := run.session.Findings()
	captured := retainedScanOutput(run.session.OutputSnapshot())

	r.mu.Lock()
	finished := time.Now()
	run.Scan.FinishedAt = finished.Format("2006-01-02T15:04:05")
	run.Scan.DurationMS = finished.Sub(row.StartedAt).Milliseconds()
	run.Scan.Findings = len(findings)
	run.Scan.Severities = api.SeverityCounts(findings)
	run.Scan.Hosts = hostsOf(findings)
	run.Scan.Stats = run.Output.Snapshot().Stats
	run.Scan.OutputCaptured = true
	run.Scan.Stdout = captured.Stdout
	run.Scan.Stderr = captured.Stderr
	run.Scan.StdoutTruncated = captured.StdoutTruncated
	run.Scan.StderrTruncated = captured.StderrTruncated

	// The engine runs in this process, so there is no exit status to report.
	// The code is kept because it is what the UI, the API and the scans table
	// already speak: 0 ran, 1 did not. Why it did not is in Error, which is the
	// only place that ever carried the answer.
	exitCode := 0
	switch {
	// Asked of the session, not of ctx: cancelling a run cancels the context the
	// session derived for the engine, which leaves this one untouched. Reading
	// ctx here recorded every cancelled scan as failed.
	case run.session.Cancelled():
		run.Scan.Phase = api.PhaseCancelled
		exitCode = 1
	case runErr != nil:
		run.Scan.Phase = api.PhaseFailed
		run.Scan.Error = runErr.Error()
		exitCode = 1
	default:
		run.Scan.Phase = api.PhaseDone
	}
	run.Scan.ExitCode = &exitCode

	row.Phase = string(run.Scan.Phase)
	row.FinishedAt = &finished
	row.DurationMS = run.Scan.DurationMS
	row.ExitCode = &exitCode
	row.Command = run.Scan.Command
	row.Severities = models.Wrap(&run.Scan.Severities)
	row.Stats = models.Wrap(run.Scan.Stats)
	if run.Scan.Error != "" {
		row.Error = &run.Scan.Error
	}

	persist := context.WithoutCancel(ctx)
	if err := r.Store.FinalizeScan(persist, store.FinalizeScanOptions{
		Scan: row, Output: captured, Findings: findings,
	}); err != nil {
		run.Scan.Phase = api.PhaseFailed
		run.Scan.Error = fmt.Sprintf("persist scan evidence: %v", err)
	}
	r.publish()
	r.mu.Unlock()
}

// progressInterval is how often a running scan repaints. Fast enough to look
// live, slow enough that a scan issuing thousands of requests a second does not
// spend its time publishing.
const progressInterval = time.Second

// trackProgress republishes the run's stats on a ticker and returns a function
// that stops it.
func (r *Runtime) trackProgress(scanTask *task.Task, run *Run) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)
		ticker := time.NewTicker(progressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				stats := run.Output.Snapshot().Stats
				if stats == nil {
					continue
				}
				updateTaskProgress(scanTask, stats)
				r.mu.Lock()
				run.Scan.Stats = stats
				r.publish()
				r.mu.Unlock()
			}
		}
	}()

	return func() {
		close(done)
		<-stopped
	}
}
