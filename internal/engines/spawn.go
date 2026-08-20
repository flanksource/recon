package engines

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/flanksource/clicky/exec"
	"github.com/flanksource/clicky/task"
)

// Invocation is one engine process: where it runs, what it is fed, and where its
// output goes. Both runtimes spawn engines this way, so the process-group
// handling and the scratch directory are written once.
type Invocation struct {
	// Bin is the resolved engine binary.
	Bin string

	// Args is the full command line, from the engine's own Args method.
	Args []string

	// WorkDir is the per-run scratch directory. Created before the process
	// starts and removed by Cleanup.
	WorkDir string

	// Stdout and Stderr receive the process output as it arrives. Either may be
	// nil.
	Stdout, Stderr io.Writer

	// Env adds to the process environment rather than replacing it. An engine
	// that authenticates against a cloud provider reads its credentials from
	// there, and a replaced environment would lose the PATH and HOME the
	// provider's own SDK needs to find them.
	Env map[string]string

	mu      sync.Mutex
	process *exec.Process
}

// NewWorkDir creates a scratch directory for one run under root. Per-run rather
// than a fixed path: the previous implementation reused `.gen/app-scan.txt`, so
// a scan started from the CLI and one started from the UI overwrote each
// other's input list.
// The path is absolute: the engine runs with its working directory set here, so
// a relative input path would resolve against the scratch directory itself and
// point at nothing.
func NewWorkDir(root, kind, id string) (string, error) {
	dir := filepath.Join(root, ".gen", kind+"-"+id)
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve work dir: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o755); err != nil {
		return "", fmt.Errorf("create work dir: %w", err)
	}
	return absolute, nil
}

// WriteList renders an input list — one entry per line — and returns its path.
func WriteList(dir, name string, entries []string) (string, error) {
	if len(entries) == 0 {
		return "", fmt.Errorf("refusing to write an empty %s: an engine given no input reports no findings, which is not the same as finding nothing", name)
	}

	path := filepath.Join(dir, name)
	body := strings.Join(entries, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", fmt.Errorf("write %s: %w", name, err)
	}
	return path, nil
}

// Result is how an engine process ended.
type Result struct {
	ExitCode int
	Err      error
	Command  []string
}

// Run starts the engine and waits for it.
//
// WithProcessGroup is not optional: naabu forks raw-socket workers and nuclei
// spawns helpers, and clicky's atomic kill path needs the group to exist —
// without it, cancelling falls back to walking descendants and can leave
// scanners running against live infrastructure.
func (i *Invocation) Run(ctx context.Context) Result {
	process := exec.NewExec(i.Bin, i.Args...).
		WithCwd(i.WorkDir).
		WithProcessGroup()

	if len(i.Env) > 0 {
		process = process.WithEnv(i.Env)
	}

	if i.Stdout != nil || i.Stderr != nil {
		process = process.Stream(i.Stdout, i.Stderr)
	}

	i.mu.Lock()
	i.process = process
	i.mu.Unlock()

	// Cancellation has to reach the process group, so watch the context rather
	// than relying on the child noticing.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = i.Cancel()
		case <-done:
		}
	}()

	finished := process.Run()
	command := append([]string{i.Bin}, i.Args...)

	result := Result{ExitCode: finished.ExitCode(), Command: command}
	if outcome := finished.Result(); outcome != nil {
		result.Err = outcome.Error
	}
	return result
}

// OutputSnapshot returns the process output captured alongside any live stream.
func (i *Invocation) OutputSnapshot() task.OutputSnapshot {
	i.mu.Lock()
	process := i.process
	i.mu.Unlock()
	if process == nil {
		return task.OutputSnapshot{}
	}
	return task.OutputSnapshot{Stdout: process.GetStdout(), Stderr: process.GetStderr()}
}

// TaskDetails projects the process metadata understood by Clicky's task UI.
func (i *Invocation) TaskDetails() exec.ExecTaskDetails {
	i.mu.Lock()
	process := i.process
	i.mu.Unlock()
	if process == nil {
		return exec.ExecTaskDetails{Command: i.Bin, Args: append([]string(nil), i.Args...), Status: "pending", ExitCode: -1}
	}
	result := process.Result()
	return exec.ExecTaskDetails{
		Command: result.Command, Args: append([]string(nil), result.Args...), PID: result.PID,
		Status: result.Status, ExitCode: result.ExitCode, Started: result.Started, Duration: result.Duration,
	}
}

// Cancel kills the engine and everything it started.
func (i *Invocation) Cancel() error {
	i.mu.Lock()
	process := i.process
	i.mu.Unlock()

	if process == nil {
		return nil
	}
	return process.KillTree()
}

// Cleanup removes the scratch directory.
func (i *Invocation) Cleanup() {
	if i.WorkDir != "" {
		_ = os.RemoveAll(i.WorkDir)
	}
}
