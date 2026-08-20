package scan

import (
	"context"
	"sync"
	"time"

	clickyexec "github.com/flanksource/clicky/exec"
	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
)

// session is one engine execution and everything it produced.
//
// It replaces the subprocess the runtime used to supervise. The engine is linked
// in, so there is no pipe to drain and no exit status to read: findings, stats
// and log lines arrive as calls, and stopping the run means cancelling its
// context rather than signalling a process group.
//
// It implements enginescan.Sink, so the engine writes here directly and the
// runtime reads the same object.
type session struct {
	// Command is the equivalent command-line invocation. Nothing runs it for an
	// in-process engine; it is recorded so a run can be reproduced by hand.
	Command []string

	// engine names what is running, for the task console to label a run whose
	// engine describes no equivalent command line.
	engine string

	output *Output

	mu       sync.Mutex
	findings []api.Finding
	started  time.Time
	finished time.Time
	status   string
	failure  error
	cancel   context.CancelFunc
}

var _ enginescan.Sink = (*session)(nil)

func newSession(output *Output, engine string, command []string) *session {
	return &session{output: output, engine: engine, Command: command, status: "pending"}
}

// Finding records one result. Findings are kept in memory for the duration of
// the run because the runtime summarises them — counts, severities, affected
// hosts — the moment it ends; the durable copy is the JSONL the engine writes.
func (s *session) Finding(finding api.Finding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.findings = append(s.findings, finding)
	return nil
}

func (s *session) Stats(stats api.ScanStats) { s.output.SetStats(stats) }

// Log attributes engine output to stdout. In-process there is no second stream:
// the distinction only ever described which pipe a subprocess chose, and
// inventing one here would be a fiction the console renders as fact.
func (s *session) Log(text string) { s.output.Append(StreamStdout, text) }

// Findings returns what the run produced so far.
func (s *session) Findings() []api.Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]api.Finding(nil), s.findings...)
}

// Run executes the engine and records how it ended.
func (s *session) Run(ctx context.Context, engine enginescan.Engine, run engines.Run) error {
	ctx, cancel := context.WithCancel(ctx)

	s.mu.Lock()
	s.cancel = cancel
	s.started = time.Now()
	s.status = "running"
	s.mu.Unlock()
	defer cancel()

	err := engine.Run(ctx, run, s)

	s.mu.Lock()
	s.finished = time.Now()
	s.failure = err
	switch {
	case ctx.Err() != nil:
		s.status = "cancelled"
	case err != nil:
		s.status = "failed"
	default:
		s.status = "completed"
	}
	s.mu.Unlock()
	return err
}

// Cancelled reports that the run was stopped rather than allowed to finish.
//
// The session owns the cancellable context — Cancel derives it from the caller's
// and cancels only its own — so the caller's context stays clean and cannot be
// asked. Without this a cancelled scan is recorded as failed, because the error
// the engine returns for "you cancelled me" is still an error.
func (s *session) Cancelled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status == "cancelled"
}

// Cancel stops the run. Safe before it starts and after it ends.
func (s *session) Cancel() error {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

// OutputSnapshot feeds clicky's task console.
func (s *session) OutputSnapshot() task.OutputSnapshot {
	return task.OutputSnapshot{Stdout: s.output.Snapshot().Log}
}

// TaskDetails describes the run to clicky's task UI in the vocabulary it
// already renders. ExitCode is 0 or 1 rather than a real status: there is no
// process, and the reason a run failed is on the scan's Error field, not
// compressed into a number.
func (s *session) TaskDetails() clickyexec.ExecTaskDetails {
	s.mu.Lock()
	defer s.mu.Unlock()

	details := clickyexec.ExecTaskDetails{
		Command: s.engine,
		Status:  s.status,
	}
	if !s.started.IsZero() {
		started := s.started
		details.Started = &started
	}
	if len(s.Command) > 1 {
		details.Command = s.Command[0]
		details.Args = append([]string(nil), s.Command[1:]...)
	}
	switch s.status {
	case "pending", "running":
		details.ExitCode = -1
	case "completed":
		details.ExitCode = 0
	default:
		details.ExitCode = 1
	}
	if !s.finished.IsZero() {
		details.Duration = s.finished.Sub(s.started)
	}
	return details
}
