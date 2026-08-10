package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/flanksource/recon/internal/api"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/models"
)

// supervise waits for the engine, then records what it found.
func (r *Runtime) supervise(
	ctx context.Context,
	run *Run,
	engine enginescan.Engine,
	row models.Scan,
	resultPath string,
) {
	defer close(run.done)
	defer run.cancel()
	defer run.invocation.Cleanup()

	timer := time.AfterFunc(maxDuration, func() {
		run.Output.Append(StreamSystem,
			fmt.Sprintf("[!] scan exceeded %s and was cancelled\n", maxDuration))
		r.Cancel()
	})
	defer timer.Stop()

	result := run.invocation.Run(ctx)
	run.Output.Flush()
	findings, parseErr := r.collect(engine, resultPath)

	r.mu.Lock()
	finished := time.Now()
	run.Scan.FinishedAt = finished.Format("2006-01-02T15:04:05")
	run.Scan.ExitCode = &result.ExitCode
	run.Scan.Findings = len(findings)
	run.Scan.Severities = api.SeverityCounts(findings)
	run.Scan.Hosts = hostsOf(findings)
	run.Scan.Stats = run.Output.Snapshot().Stats

	switch {
	case ctx.Err() != nil:
		run.Scan.Phase = api.PhaseCancelled
	case result.ExitCode != 0:
		run.Scan.Phase = api.PhaseFailed
		run.Scan.Error = errorText(result.Err, result.ExitCode)
	case parseErr != nil:
		run.Scan.Phase = api.PhaseDone
		run.Scan.Error = parseErr.Error()
	default:
		run.Scan.Phase = api.PhaseDone
	}

	row.Phase = string(run.Scan.Phase)
	row.FinishedAt = &finished
	row.ExitCode = &result.ExitCode
	row.Command = result.Command
	row.Severities = models.Wrap(&run.Scan.Severities)
	row.Stats = models.Wrap(run.Scan.Stats)
	if run.Scan.Error != "" {
		row.Error = &run.Scan.Error
	}

	persist := context.WithoutCancel(ctx)
	if err := r.Store.SaveFindings(persist, row.ID, findings); err != nil {
		run.Scan.Error = err.Error()
	}
	if err := r.Store.UpdateScan(persist, row); err != nil {
		run.Scan.Error = err.Error()
	}
	r.publish()
	phase, problem := run.Scan.Phase, run.Scan.Error
	r.mu.Unlock()

	finishManagedScan(run.managed, phase, problem)
}
