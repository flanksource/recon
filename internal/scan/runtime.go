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
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/models"
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
	Store       *store.Store
	Provisioner *engines.Provisioner
	Publisher   Publisher
	Root        string

	mu      sync.Mutex
	current *Run
}

// Run is one scan, live or finished.
type Run struct {
	Scan   api.Scan
	Output *Output

	invocation *engines.Invocation
	cancel     context.CancelFunc

	// done closes when the run reaches a terminal phase. Wait blocks on it.
	done chan struct{}
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
		Running: !r.current.Scan.Phase.Terminal(),
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
// The order of checks is the order the UI expects to see them fail in: already
// running, then the engine, then the profile, then what the selector actually
// resolves to, and only then the risk gate — so "no endpoints match" is
// reported before being asked to confirm a scan of nothing.
func (r *Runtime) Start(ctx context.Context, request Request) (api.Scan, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.Store == nil {
		return api.Scan{}, fmt.Errorf("scan runtime has no database: it was not wired up")
	}
	if r.Provisioner == nil {
		return api.Scan{}, fmt.Errorf("scan runtime has no provisioner: it was not wired up")
	}
	if r.current != nil && !r.current.Scan.Phase.Terminal() {
		return api.Scan{}, fmt.Errorf("a scan is already running: %s", r.current.Scan.Name)
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

	endpoints, err := r.Store.Endpoints(ctx, request.Selector)
	if err != nil {
		return api.Scan{}, err
	}
	if len(endpoints) == 0 {
		return api.Scan{}, fmt.Errorf(
			"no endpoints match %s: nothing to scan", request.Selector.Describe())
	}

	if risk := engine.Risk(config); risk.Intrusive && !request.Confirmed {
		if risky := store.Risky(endpoints); len(risky) > 0 {
			return api.Scan{}, fmt.Errorf(
				"refusing an %s against %d host(s) that are production, public or unclassified (%s): re-run with confirmation",
				risk, len(risky), summarise(store.Hosts(risky)))
		}
	}

	bin, err := r.Provisioner.Resolve(spec)
	if err != nil {
		return api.Scan{}, err
	}

	return r.launch(ctx, engine, bin, config, endpoints, request)
}

// resolveConfig layers the run-only overrides over the stored profile and
// validates the result, so a run cannot use a configuration the engine's own
// catalog would reject.
func (r *Runtime) resolveConfig(ctx context.Context, spec engines.Spec, request Request) (map[string]any, error) {
	profile, err := r.Store.GetProfile(ctx, "scan:"+spec.Name+":"+request.Profile)
	if err != nil {
		return nil, err
	}

	config := map[string]any{}
	for key, value := range profile.Config {
		config[key] = value
	}
	for key, value := range request.Overrides {
		config[key] = value
	}

	if err := spec.Sections.Validate(config); err != nil {
		return nil, fmt.Errorf("scan configuration: %w", err)
	}
	return config, nil
}

func (r *Runtime) launch(
	ctx context.Context,
	engine enginescan.Engine,
	bin string,
	config map[string]any,
	endpoints []store.Endpoint,
	request Request,
) (api.Scan, error) {
	spec := engine.Spec()
	started := time.Now()
	name := fmt.Sprintf("%s-%s-%s", spec.Name, request.Profile, started.Format("20060102-150405"))

	row, err := r.Store.CreateScan(ctx, models.Scan{
		Name:          name,
		Engine:        spec.Name,
		Profile:       request.Profile,
		Selector:      models.Wrap(selectorMap(request.Selector)),
		EndpointCount: len(endpoints),
		Phase:         string(api.PhaseRunning),
		StartedAt:     started,
	})
	if err != nil {
		return api.Scan{}, err
	}

	dir, err := engines.NewWorkDir(r.Root, "scan", row.ID)
	if err != nil {
		return api.Scan{}, err
	}

	targets := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		targets = append(targets, endpoint.URL)
	}
	in, err := engines.WriteList(dir, "targets.txt", targets)
	if err != nil {
		return api.Scan{}, err
	}

	out := filepath.Join(dir, "findings.jsonl")
	group := task.StartGroup[any](name,
		task.WithKind("scan"), task.WithConcurrency(1),
		task.WithLabels(map[string]string{"engine": spec.Name, "profile": request.Profile}))

	// The group exists for supervision and for /api/tasks visibility. The status
	// the UI reads is derived from Run, never from the task snapshot: a task
	// knows nothing about findings or severities.
	_ = group

	output := NewOutput(progressOf(engine))
	invocation := &engines.Invocation{
		Bin:     bin,
		Args:    engine.Args(engines.Run{Bin: bin, WorkDir: dir, Config: config, In: in, Out: out}),
		WorkDir: dir,
		Stdout:  streamWriter{output: output, stream: StreamStdout, notify: r.publish, runtime: r},
		Stderr:  streamWriter{output: output, stream: StreamStderr, notify: r.publish, runtime: r},
	}

	runCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	run := &Run{
		Scan:       row.Document(0, nil, request.Selector.Describe()),
		Output:     output,
		invocation: invocation,
		cancel:     cancel,
		done:       make(chan struct{}),
	}
	run.Scan.Command = append([]string{bin}, invocation.Args...)
	r.current = run
	r.publish()

	go r.supervise(runCtx, run, engine, row, out)
	return run.Scan, nil
}

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

	// A wall-clock bound rather than the process timeout, so an overrunning scan
	// ends as cancelled rather than failed — it was stopped, not broken.
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
	defer r.mu.Unlock()

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
		// The engine succeeded, so its findings are real; the damage is in the
		// output file and must be reported rather than hidden.
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
}

// collect reads the findings the engine wrote.
func (r *Runtime) collect(engine enginescan.Engine, path string) ([]api.Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// A scan that matched nothing writes no file. That is a clean run
			// with no findings, not a failure.
			return nil, nil
		}
		return nil, fmt.Errorf("read findings: %w", err)
	}
	defer file.Close()

	var findings []api.Finding
	parseErr := engine.Parse(file, func(finding api.Finding) error {
		findings = append(findings, finding)
		return nil
	})
	return findings, parseErr
}

// Wait blocks until the current run finishes and returns how it ended.
//
// The CLI needs this: a scan runs in a goroutine, so a command that returned as
// soon as the engine started would exit and take the run with it, leaving the
// row stuck at "running" forever. The server does not wait — that is what the
// event stream is for.
func (r *Runtime) Wait(ctx context.Context) (api.Scan, error) {
	r.mu.Lock()
	run := r.current
	r.mu.Unlock()

	if run == nil {
		return api.Scan{}, fmt.Errorf("no scan has been started")
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
	run.cancel()
	return run.invocation.Cancel()
}

// streamWriter feeds one pipe into the buffer and publishes as it goes.
type streamWriter struct {
	output  *Output
	stream  Stream
	notify  func()
	runtime *Runtime
}

func (w streamWriter) Write(p []byte) (int, error) {
	w.output.Append(w.stream, string(p))
	// Take the lock to publish: the snapshot has to be consistent with whatever
	// the supervising goroutine is writing.
	w.runtime.mu.Lock()
	w.runtime.publish()
	w.runtime.mu.Unlock()
	return len(p), nil
}

// progressOf returns the engine's progress parser, or nil when it reports none.
func progressOf(engine enginescan.Engine) enginescan.Progress {
	parser, ok := engine.(enginescan.Progress)
	if !ok {
		return nil
	}
	return parser
}

func selectorMap(opts store.TargetOpts) *map[string]any {
	stored := opts.Map()
	return &stored
}

func hostsOf(findings []api.Finding) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, finding := range findings {
		if finding.Host != "" && !seen[finding.Host] {
			seen[finding.Host] = true
			hosts = append(hosts, finding.Host)
		}
	}
	return hosts
}

func errorText(err error, code int) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("engine exited %d", code)
}

// summarise names the first few hosts and counts the rest. A prompt that says
// "3 production hosts" without saying which is not one anyone can answer.
func summarise(hosts []string) string {
	const shown = 3
	if len(hosts) <= shown {
		return joinHosts(hosts)
	}
	return fmt.Sprintf("%s and %d more", joinHosts(hosts[:shown]), len(hosts)-shown)
}

func joinHosts(hosts []string) string {
	out := ""
	for i, host := range hosts {
		if i > 0 {
			out += ", "
		}
		out += host
	}
	return out
}
