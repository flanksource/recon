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
	"github.com/flanksource/recon/internal/mute"
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

	// Applied here, over the whole slice, rather than in the sink: the sink is
	// the engine's hot path — nuclei calls it from its worker pool for every
	// match — and its contract is that an error aborts the run, so a mistyped
	// expression would kill a scan halfway through. Applied before the counts
	// below, so a muted finding is absent from every one of them.
	muted := mute.Apply(run.pushdown.Deferred(run.mutes), run.session.Findings())
	findings := muted.Kept
	run.Output.Append(StreamSystem, muted.Summary(run.mutes)+"\n")
	for name, reason := range muted.Errors {
		run.Output.Append(StreamSystem,
			fmt.Sprintf("[!] mute rule %s was not applied: %s\n", name, reason))
	}

	captured := retainedScanOutput(run.session.OutputSnapshot())

	r.mu.Lock()
	finished := time.Now()
	run.Scan.FinishedAt = finished.Format("2006-01-02T15:04:05")
	run.Scan.DurationMS = finished.Sub(row.StartedAt).Milliseconds()
	run.Scan.Findings = len(findings)
	run.Scan.Muted = muted.Muted
	run.Scan.Severities = api.SeverityCounts(findings)
	run.Scan.Hosts = hostsOf(findings)
	run.Scan.Stats = run.Output.Snapshot().Stats
	run.Scan.Result = run.artifacts.Dir
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
	row.Muted = run.Scan.Muted
	row.Stats = models.Wrap(run.Scan.Stats)
	row.ResultPath = &run.artifacts.Dir
	if run.Scan.Error != "" {
		row.Error = &run.Scan.Error
	}

	// The engine wrote its own findings file as it went; these are what recon
	// knows that the engine does not. Written before the database so a
	// terminal run's directory is complete whether or not the write below is.
	if err := run.retainArtifacts(captured, muteRecord(run.mutes, run.pushdown, muted)); err != nil {
		run.Scan.Phase = api.PhaseFailed
		// Appended rather than assigned: a run that both failed and could not
		// write its evidence has two problems, and the engine's own error is
		// the one that says why it failed.
		if run.Scan.Error != "" {
			run.Scan.Error += "; "
		}
		run.Scan.Error += err.Error()
		row.Phase = string(api.PhaseFailed)
		row.Error = &run.Scan.Error
	}

	persist := context.WithoutCancel(ctx)
	if err := r.Store.FinalizeScan(persist, store.FinalizeScanOptions{
		Scan: row, Output: captured, Findings: findings,
		// Every target the selector resolved to, not only the ones with findings:
		// "this target was scanned and nothing was found" is the answer the
		// inventory's Last scan column exists to give.
		TargetIDs: run.targetIDs, CountFindings: true,
		// Every subject the run examined, passes included — the half of the
		// estate that used to be invisible because only failures left a trace.
		Resources: run.session.Resources(),
		// The findings a rule removed. They are not written, so without them a
		// check somebody accepted would keep whatever state it had and read as
		// a problem nobody is looking at.
		Muted: muted.Dropped, MutedBy: muted.ByRule,
	}); err != nil {
		run.Scan.Phase = api.PhaseFailed
		run.Scan.Error = fmt.Sprintf("persist scan evidence: %v", err)
	}
	r.publish()
	r.mu.Unlock()
}

// retainArtifacts writes the run's own record alongside the engine's output.
//
// The log is stored as a file rather than only in the database because the
// directory has to stand on its own: someone reading `results/` a month later
// should not need Postgres running to find out what the scan said.
func (r *Run) retainArtifacts(captured models.ScanOutput, mutes MuteRecord) error {
	log := captured.Stdout
	if captured.Stderr != "" {
		log += captured.Stderr
	}
	if err := r.artifacts.WriteFile(LogFile, []byte(log)); err != nil {
		return fmt.Errorf("retain scan artifacts: %w", err)
	}

	// Written whether or not anything was muted, and written here because a
	// muted finding is not recorded anywhere else: the engine's own findings
	// file still holds every line it produced, and this is what says which of
	// those lines the database does not have and which rule removed them.
	if err := r.artifacts.WriteJSON(MutesFile, mutes); err != nil {
		return fmt.Errorf("retain scan artifacts: %w", err)
	}

	// The estate the run saw, passes included. The engine's own output records
	// only what failed, so this is the only file in the directory that says
	// what was clean.
	if err := r.artifacts.WriteJSONL(ResourcesFile, r.session.Resources()); err != nil {
		return fmt.Errorf("retain scan artifacts: %w", err)
	}

	// The captured streams are dropped from the record: they are the file that
	// was just written, and embedding a megabyte of console output in the
	// metadata makes the one file anyone opens by hand the one nobody can read.
	record := r.Scan
	record.Stdout, record.Stderr = "", ""
	if err := r.artifacts.WriteJSON(MetadataFile, record); err != nil {
		return fmt.Errorf("retain scan artifacts: %w", err)
	}
	return nil
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
