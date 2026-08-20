// Package probes runs liveness sweeps over selected inventory targets and
// records what answered.
//
// A sweep is deliberately not a discovery run: it enumerates nothing and runs no
// engine. It takes hosts that are already in the inventory, checks whether they
// answer, folds the answer into each target's observed state, and records the
// run.
package probes

import (
	"context"
	"fmt"
	"time"

	"github.com/flanksource/clicky/task"
	flanksourceContext "github.com/flanksource/commons/context"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/observe"
	"github.com/flanksource/recon/internal/probe"
	"github.com/flanksource/recon/internal/store"
)

// Runner owns liveness sweeps.
type Runner struct {
	Store *store.Store
}

// Options is what starts a sweep. Hosts are already resolved and deduplicated:
// which targets a selector matches is the caller's question, and answering it
// twice would let the run and its record disagree.
type Options struct {
	Selector        store.TargetOpts
	Hosts           []string
	Timeout         time.Duration
	Concurrency     int
	FollowRedirects bool

	// Wait blocks until every host has been probed. The CLI wants this; the
	// browser passes false and follows the run, because a sweep of the estate
	// outlasts any sensible request timeout.
	Wait bool
}

// Run probes every host and records what answered.
func (r *Runner) Run(ctx context.Context, opts Options) (api.ProbeRun, error) {
	if r.Store == nil {
		return api.ProbeRun{}, fmt.Errorf("probe runner has no database: it was not wired up")
	}
	if len(opts.Hosts) == 0 {
		return api.ProbeRun{}, fmt.Errorf("no hosts to probe")
	}
	if opts.Timeout <= 0 {
		return api.ProbeRun{}, fmt.Errorf("probe timeout must be greater than zero, got %s", opts.Timeout)
	}
	if opts.Concurrency <= 0 {
		return api.ProbeRun{}, fmt.Errorf("probe concurrency must be greater than zero, got %d", opts.Concurrency)
	}

	selector, err := opts.Selector.Map()
	if err != nil {
		return api.ProbeRun{}, err
	}

	started := time.Now()
	row := models.Probe{
		Selector:        models.Wrap(&selector),
		Total:           len(opts.Hosts),
		TimeoutMS:       int(opts.Timeout.Milliseconds()),
		Concurrency:     opts.Concurrency,
		FollowRedirects: opts.FollowRedirects,
		Phase:           string(api.PhaseRunning),
		RanAt:           started,
	}
	// Recorded before any traffic, so a crashed process still leaves evidence
	// that something was attempted — the same reason CreateScan comes first.
	if err := r.Store.CreateProbe(ctx, &row); err != nil {
		return api.ProbeRun{}, err
	}
	scan, err := r.recordScan(ctx, row, opts, selector, started)
	if err != nil {
		return api.ProbeRun{}, err
	}

	// Every store write below outlives the request: with Wait false the caller's
	// context is cancelled as soon as the response is written, and a sweep that
	// stopped persisting at that moment would leave the run stuck at running
	// forever.
	persist := context.WithoutCancel(ctx)

	group := newTaskGroup(row.ID, opts.Selector.Describe(), len(opts.Hosts), opts.Concurrency)
	options := probe.Options{Timeout: opts.Timeout, FollowRedirects: opts.FollowRedirects}
	for _, host := range opts.Hosts {
		r.addHost(persist, group, row.ID, host, options)
	}

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		r.finish(persist, group, row, scan, opts.Hosts, started)
	}()

	if !opts.Wait {
		// The run as it stands: created, running, nothing probed yet. The caller
		// follows it from here by id.
		return r.Store.GetProbe(persist, row.ID)
	}

	<-finished
	return r.Store.GetProbe(persist, row.ID)
}

// addHost queues one host.
//
// The task's context is clicky's alone. Composing the caller's in — the idiom
// `reconctl ping` and discovery both use — is right for a caller that blocks and
// fatal here: with Wait false the request context is already dead by the time
// the first host is dequeued, and every probe would be cancelled before it ran.
func (r *Runner) addHost(
	ctx context.Context,
	group task.TypedGroup[api.ProbeResult],
	probeID, host string,
	options probe.Options,
) {
	group.Add(host, func(taskCtx flanksourceContext.Context, t *task.Task) (api.ProbeResult, error) {
		t.SetController(hostTaskController{task: t})

		result := probeHost(taskCtx, host, options)
		t.SetDescription(describe(result))
		t.SetDetailsProvider(func() any { return result })

		updated, err := r.record(ctx, host, result)
		if err != nil {
			// The only real failure: the host answered — or did not — and we could
			// not write down which.
			return result, err
		}
		result.Updated = updated

		if err := r.Store.SaveProbeResult(ctx, models.ProbeResultFrom(probeID, result, time.Now())); err != nil {
			return result, err
		}

		// A host that did not answer is the answer, not a failure: finding them is
		// what the sweep is for, and failing here would paint a successful sweep
		// of a dead estate entirely red.
		if !result.Up {
			t.Warning()
		}
		return result, nil
	}, taskOptions(options.Timeout)...)
}

// record folds a result into the host's inventory entry.
//
// Written as each host finishes rather than in one pass at the end, so a
// target's observed state is current the moment that host is probed instead of
// after the slowest host in the estate.
func (r *Runner) record(ctx context.Context, host string, result api.ProbeResult) (bool, error) {
	stored, err := r.Store.GetTarget(ctx, host)
	if err != nil {
		if store.IsNotFound(err) {
			// Named explicitly but never inventoried, so there is no curated record
			// to update — and inventing one is discovery's job, not a refresh's.
			return false, nil
		}
		return false, err
	}

	stored, err = observe.ApplyProbe(stored, observation(result), time.Now().Format(time.RFC3339Nano))
	if err != nil {
		return false, err
	}
	if err := r.Store.SaveTarget(ctx, stored); err != nil {
		return false, err
	}
	return true, nil
}

// recordScan mirrors the sweep into the scans table.
//
// A sweep is not an engine run — nothing is compiled in for it and no profile
// configures it — but it is a run that covered a set of hosts at a time, which is
// what that table holds. Recording it there is what puts a ping in the runs list
// and, through FinalizeScan, what stamps each host's scan.last_scan.
//
// The id is the probe's own, so /api/v1/probe/{id}, /api/v1/scan/{id} and
// /api/v1/tasks/{id} all describe the same sweep — the rule the task group id
// already follows.
func (r *Runner) recordScan(
	ctx context.Context,
	row models.Probe,
	opts Options,
	selector map[string]any,
	started time.Time,
) (models.Scan, error) {
	scan, err := r.Store.CreateScan(ctx, models.Scan{
		ID:            row.ID,
		Name:          api.ProbeEngine + "-" + api.ProbeProfile + "-" + started.Format("20060102-150405.000000000"),
		Engine:        api.ProbeEngine,
		Profile:       api.ProbeProfile,
		Selector:      models.Wrap(&selector),
		EndpointCount: len(opts.Hosts),
		Phase:         string(api.PhaseRunning),
		StartedAt:     started,
	})
	if err != nil {
		return models.Scan{}, fmt.Errorf("record probe %s as a run: %w", row.ID, err)
	}
	return scan, nil
}

// finish waits for every host and writes the run's terminal state to both the
// probe and the scan it was recorded as.
func (r *Runner) finish(
	ctx context.Context,
	group task.TypedGroup[api.ProbeResult],
	row models.Probe,
	scan models.Scan,
	hosts []string,
	started time.Time,
) {
	group.WaitFor()

	finished := time.Now()
	row.FinishedAt = &finished
	row.DurationMS = int(finished.Sub(started).Milliseconds())
	row.Phase = string(phaseOf(group.Status()))

	scan.Phase = row.Phase
	scan.FinishedAt = &finished
	scan.DurationMS = int64(row.DurationMS)
	// Findings are not counted: a sweep cannot produce any, and zeroing every
	// covered host would erase what the last real scan found.
	if err := r.Store.FinalizeScan(ctx, store.FinalizeScanOptions{
		Scan: scan, Hosts: hosts,
	}); err != nil {
		// Appended rather than assigned, and reported on the probe rather than
		// swallowed: nothing above this is still listening, and a run whose
		// evidence half landed should say so.
		text := fmt.Sprintf("record probe as a run: %v", err)
		row.Error = &text
		row.Phase = string(api.PhaseFailed)
	}

	if err := r.Store.FinishProbe(ctx, row); err != nil {
		// Nothing above this to report to — the caller may already have its
		// response. Recorded on the run itself so the failure is not silent.
		text := err.Error()
		row.Error = &text
		row.Phase = string(api.PhaseFailed)
		_ = r.Store.FinishProbe(ctx, row)
	}
}

// phaseOf maps the task group's verdict onto the run's phase.
//
// A group is only failed when a host's result could not be recorded; a host
// that did not answer warns, and a warning is a completed sweep.
func phaseOf(status task.Status) api.Phase {
	switch status {
	case task.StatusFailed:
		return api.PhaseFailed
	case task.StatusCancelled:
		return api.PhaseCancelled
	default:
		return api.PhaseDone
	}
}
