// Package scan runs a scan engine over a resolved selection of endpoints and
// reports what it finds.
//
// A scan is deliberately not a discovery sweep: it does not enumerate anything.
// It takes a selector, resolves it to endpoints, and points one engine at them.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/runtimecontext"
	"github.com/flanksource/recon/internal/store"
)

// maxDuration bounds a run. A scan that has not finished in half an hour has
// either wedged or is scanning far more than anyone intended.
const maxDuration = 30 * time.Minute

// Request is what starts a scan.
type Request struct {
	Engine   string
	Profile  string
	Selector store.TargetOpts

	// Overrides are run-only tweaks layered over the stored profile. They are
	// not persisted: the profile stays what it is, and the effective config is
	// recorded on the run instead.
	Overrides map[string]any

	// Confirmed acknowledges an intrusive scan of hosts that matter. Without
	// it, such a run is refused rather than started.
	Confirmed bool
}

// Publisher receives a snapshot whenever a run changes. The SSE broadcaster
// satisfies this; nothing here depends on how it is delivered.
type Publisher interface {
	Publish(v any) error
}

// Runtime owns the one scan that may be running.
//
// One at a time, and the current run survives its own completion: the UI shows
// the last result until the next one starts, so discarding it on exit would
// blank the panel the moment a scan finished.
type Runtime struct {
	Store          *store.Store
	Provisioner    *engines.Provisioner
	ContextFactory runtimecontext.Factory
	Publisher      Publisher
	Root           string
	Concurrency    int

	mu      sync.Mutex
	current *Run
	runs    map[string]*Run
	queue   *scanQueue
}

// Run is one scan, live or finished.
type Run struct {
	Scan   api.Scan
	Output *Output

	artifacts Artifacts
	session   *session
	task      *task.Task
	queueDone func()
	row       models.Scan

	// targetIDs are the stable inventory subjects the selector resolved,
	// deduplicated. Distinct from Scan.Hosts, which are provider or network
	// identities found in the evidence.
	targetIDs []string

	// done closes when the run reaches a terminal phase. Wait blocks on it.
	done     chan struct{}
	doneOnce sync.Once
}

// SetConcurrency configures the number of scans that may run at once. It must be
// called before the first scan is accepted.
//
// An engine that runs in this process caps it at one. Nuclei's engine keeps
// global state, so two concurrent scans would interfere with each other's
// results rather than merely competing for bandwidth. Refusing is the honest
// answer: silently serialising would leave the operator believing a setting
// took effect that did not.
func (r *Runtime) SetConcurrency(concurrency int) error {
	if concurrency < 1 {
		return fmt.Errorf("scan concurrency must be at least 1, got %d", concurrency)
	}
	if concurrency > 1 {
		if serial := serialEngines(); len(serial) > 0 {
			return fmt.Errorf(
				"scan concurrency must be 1: %s runs in this process and cannot scan concurrently",
				strings.Join(serial, ", "))
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	configured := r.Concurrency
	if configured == 0 {
		configured = 1
	}
	if r.queue != nil && configured != concurrency {
		return fmt.Errorf("scan concurrency cannot change after scans have been queued")
	}
	r.Concurrency = concurrency
	return nil
}

// Status is the snapshot the UI renders. It is derived from Run rather than
// from a clicky task snapshot: the task manager knows about processes, not
// about findings, severities or an engine's progress.
//
// The output fields are named rather than embedded: OutputSnapshot also carries
// stats, and two `stats` keys in one object is not something a consumer can
// read. Stats lives on the scan, refreshed from the buffer on every snapshot so
// it is live during a run.
type Status struct {
	api.Scan
	Log     string        `json:"log"`
	Events  []OutputEvent `json:"output"`
	Running bool          `json:"running"`
}

// MarshalJSON flattens the embedded scan alongside the output fields.
//
// Without this, api.Scan's own MarshalJSON is promoted onto Status and becomes
// Status's, so encoding a Status silently emits only the scan — the log, the
// output and the running flag vanish from the stream with no error anywhere.
func (s Status) MarshalJSON() ([]byte, error) {
	encoded, err := json.Marshal(s.Scan)
	if err != nil {
		return nil, err
	}

	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}

	events := s.Events
	if events == nil {
		events = []OutputEvent{}
	}
	fields["log"] = s.Log
	fields["output"] = events
	fields["running"] = s.Running
	return json.Marshal(fields)
}

// Status returns the current run, or an idle snapshot when there has never been
// one. Always a value, never nil: the browser subscribes before anything has
// run and needs something to render.
func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status()
}

func (r *Runtime) status() Status {
	if r.current == nil {
		return Status{Scan: api.Scan{Phase: api.PhaseIdle}}
	}
	status := Status{
		Scan:    r.current.Scan,
		Running: r.current.Scan.Phase == api.PhaseRunning,
	}
	if r.current.Output != nil {
		snapshot := r.current.Output.Snapshot()
		status.Log = snapshot.Log
		status.Events = snapshot.Events
		// Live progress: the engine reports it as it goes, and the copy stored
		// on the scan row is only written when the run ends.
		status.Stats = snapshot.Stats
	}
	return status
}

// publish sends the current snapshot to subscribers. Called with the lock held.
func (r *Runtime) publish() {
	if r.Publisher == nil {
		return
	}
	// A failure to encode a snapshot must not take down a running scan; the
	// broadcaster reports it and the next snapshot supersedes this one.
	_ = r.Publisher.Publish(r.status())
}

// PublishCurrent sends the current snapshot. The server calls this at startup
// so a browser connecting before anything has run still renders a state.
func (r *Runtime) PublishCurrent() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.publish()
}

// Start validates a request and begins a scan.
//
// Validation happens before admission so an invalid request never occupies a
// queue slot. Accepted scans are recorded as queued and start when capacity is
// available.
func (r *Runtime) Start(ctx context.Context, request Request) (api.Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Store == nil {
		return api.Scan{}, fmt.Errorf("scan runtime has no database: it was not wired up")
	}
	if r.Provisioner == nil {
		return api.Scan{}, fmt.Errorf("scan runtime has no provisioner: it was not wired up")
	}
	if r.ContextFactory == nil {
		return api.Scan{}, fmt.Errorf("scan runtime has no execution context: it was not wired up")
	}
	if r.queue == nil {
		concurrency := r.Concurrency
		if concurrency == 0 {
			concurrency = 1
		}
		queue, err := newScanQueue(concurrency)
		if err != nil {
			return api.Scan{}, err
		}
		r.queue = queue
	}

	engine, err := enginescan.Get(request.Engine)
	if err != nil {
		return api.Scan{}, err
	}
	spec := engine.Spec()

	config, err := r.resolveConfig(ctx, spec, request)
	if err != nil {
		return api.Scan{}, err
	}

	subjects, err := r.subjects(ctx, spec, config, request.Selector)
	if err != nil {
		return api.Scan{}, err
	}

	if risk := engine.Risk(config); risk.Intrusive && !request.Confirmed {
		if risky := store.Risky(subjects.riskTargets()); len(risky) > 0 {
			return api.Scan{}, fmt.Errorf(
				"refusing an %s against %d host(s) that are production, public or unclassified (%s): re-run with confirmation",
				risk, len(risky), summarise(store.Hosts(risky)))
		}
	}

	return r.enqueue(ctx, engine, config, subjects, request)
}

// resolveConfig layers the run-only overrides over the stored profile and
// validates the result, so a run cannot use a configuration the engine's own
// catalog would reject.
func (r *Runtime) resolveConfig(ctx context.Context, spec engines.Spec, request Request) (map[string]any, error) {
	profile, err := r.Store.GetProfile(ctx, "scan:"+spec.Name+":"+request.Profile)
	if err != nil {
		return nil, err
	}
	if err := spec.ValidateOverrides(profile.Config, request.Overrides); err != nil {
		return nil, fmt.Errorf("scan configuration: %w", err)
	}

	config := map[string]any{}
	for key, value := range profile.Config {
		config[key] = value
	}
	for key, value := range request.Overrides {
		config[key] = value
	}

	if err := spec.ValidateConfig(config); err != nil {
		return nil, fmt.Errorf("scan configuration: %w", err)
	}
	return config, nil
}

func (r *Runtime) enqueue(
	ctx context.Context,
	engine enginescan.Engine,
	config map[string]any,
	subjects resolvedSubjects,
	request Request,
) (api.Scan, error) {
	spec := engine.Spec()
	queuedAt := time.Now()
	name := fmt.Sprintf("%s-%s-%s", spec.Name, request.Profile, queuedAt.Format("20060102-150405.000000000"))
	selector, err := selectorMap(request.Selector)
	if err != nil {
		return api.Scan{}, err
	}

	row, err := r.Store.CreateScan(ctx, models.Scan{
		Name:          name,
		Engine:        spec.Name,
		Profile:       request.Profile,
		Selector:      models.Wrap(selector),
		EndpointCount: subjects.count(),
		Phase:         string(api.PhaseQueued),
		StartedAt:     queuedAt,
	})
	if err != nil {
		return api.Scan{}, err
	}

	artifacts, err := NewArtifacts(r.Root, spec.Name, queuedAt, name)
	if err != nil {
		return api.Scan{}, r.failQueuedScan(ctx, row, err)
	}

	in, err := writeSubjects(artifacts.Dir, subjects)
	if err != nil {
		artifacts.Remove()
		return api.Scan{}, r.failQueuedScan(ctx, row, err)
	}
	// The effective configuration, not the stored profile: overrides are
	// run-only and are otherwise lost the moment the run ends.
	if err := artifacts.WriteJSON(ConfigFile, config); err != nil {
		artifacts.Remove()
		return api.Scan{}, r.failQueuedScan(ctx, row, err)
	}

	// A spawned engine needs its binary resolved before the run is built; an
	// in-process one reports a path nothing can exec. Resolving here rather than
	// at run time means a missing binary fails the request instead of a queued
	// scan that starts and immediately dies.
	bin, err := r.Provisioner.Resolve(spec)
	if err != nil {
		artifacts.Remove()
		return api.Scan{}, r.failQueuedScan(ctx, row, err)
	}

	out := artifacts.Path(FindingsFile)
	engineRun := engines.Run{
		Bin: bin, WorkDir: artifacts.Dir, Config: config, In: in, Out: out,
		ProviderContexts: engineProviderContexts(subjects.ProviderContexts),
	}
	output := NewOutput()
	current := newSession(output, spec.Name, commandOf(engine, engineRun))

	run := &Run{
		Scan:      row.Document(0, nil, request.Selector.Describe()),
		Output:    output,
		artifacts: artifacts,
		session:   current,
		row:       row,
		targetIDs: subjects.targetIDs(),
		done:      make(chan struct{}),
	}
	run.Scan.Command = current.Command
	run.Scan.Result = artifacts.Dir
	// Recorded before the engine starts, so a run that crashes still names the
	// directory holding whatever it managed to write.
	row.ResultPath = &artifacts.Dir
	row.Command = append(row.Command, run.Scan.Command...)
	run.row = row
	if err := r.Store.UpdateScan(ctx, row); err != nil {
		artifacts.Remove()
		return api.Scan{}, fmt.Errorf("persist queued scan command: %w", err)
	}
	if r.runs == nil {
		r.runs = map[string]*Run{}
	}
	r.runs[run.Scan.ID] = run
	r.current = run
	queuedTask := r.queue.Add(name, spec.Name, request.Profile, func(taskCtx context.Context, scanTask *task.Task) (api.Scan, error) {
		return r.execute(taskCtx, scanTask, run, engine, engineRun)
	}, func() error {
		return r.cancelRun(run)
	})
	run.task = queuedTask.Task
	run.queueDone = queuedTask.complete
	bindScanTask(run.task, scanTaskBinding{
		Session: current,
		Snapshot: func() api.Scan {
			r.mu.Lock()
			defer r.mu.Unlock()
			return run.Scan
		},
	})
	r.publish()
	return run.Scan, nil
}

func (r *Runtime) failQueuedScan(ctx context.Context, row models.Scan, cause error) error {
	finished := time.Now()
	row.Phase = string(api.PhaseFailed)
	row.FinishedAt = &finished
	row.Error = new(string)
	*row.Error = cause.Error()
	if err := r.Store.FinalizeScan(context.WithoutCancel(ctx), store.FinalizeScanOptions{
		Scan: row, Output: models.ScanOutput{},
	}); err != nil {
		return fmt.Errorf("%w; persist failed queued scan: %v", cause, err)
	}
	return cause
}

func (r *Runtime) execute(
	ctx context.Context,
	scanTask *task.Task,
	run *Run,
	engine enginescan.Engine,
	engineRun engines.Run,
) (api.Scan, error) {
	r.mu.Lock()
	if run.Scan.Phase.Terminal() {
		result := run.Scan
		r.mu.Unlock()
		return result, context.Canceled
	}

	started := time.Now()
	run.Scan.Phase = api.PhaseRunning
	run.Scan.StartedAt = started.Format("2006-01-02T15:04:05")
	run.row.Phase = string(api.PhaseRunning)
	run.row.StartedAt = started
	run.row.Command = run.Scan.Command
	r.current = run
	if err := r.Store.UpdateScan(context.WithoutCancel(ctx), run.row); err != nil {
		finished := time.Now()
		run.Scan.Phase = api.PhaseFailed
		run.Scan.Error = err.Error()
		run.Scan.FinishedAt = finished.Format("2006-01-02T15:04:05")
		run.doneOnce.Do(func() { close(run.done) })
		r.publish()
		result := run.Scan
		r.mu.Unlock()
		return result, err
	}
	r.publish()
	r.mu.Unlock()

	engineRun.Context = r.ContextFactory(ctx)
	r.supervise(ctx, scanTask, run, engine, run.row, engineRun)

	r.mu.Lock()
	result := run.Scan
	r.mu.Unlock()
	return result, finishScanTask(scanTask, result)
}

func finishScanTask(scanTask *task.Task, result api.Scan) error {
	switch result.Phase {
	case api.PhaseDone:
		if result.Error != "" {
			scanTask.Warning()
		}
		return nil
	case api.PhaseCancelled:
		scanTask.SetStatus(task.StatusCancelled)
		return context.Canceled
	default:
		return fmt.Errorf("scan %s failed: %s", result.Name, result.Error)
	}
}

// commandOf renders the equivalent command line for a run, when the engine can
// describe itself that way.
//
// Nothing executes it. It is recorded on the scan so the UI can show what the
// run amounted to and someone can reproduce it by hand — an in-process engine
// would otherwise leave no trace of its configuration outside the database.
func commandOf(engine enginescan.Engine, run engines.Run) []string {
	describer, ok := engine.(interface {
		Command(engines.Run) []string
	})
	if !ok {
		return nil
	}
	return describer.Command(run)
}
