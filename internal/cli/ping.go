package cli

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/api"
	"github.com/flanksource/clicky/task"
	flanksourceContext "github.com/flanksource/commons/context"
	"github.com/flanksource/commons/duration"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/probe"
)

const (
	defaultPingConcurrency = 10
	defaultPingTimeout     = 3 * time.Second
)

// PingResult is what one probe saw. Aliased rather than redeclared so the
// inventory probe and this command cannot describe a host differently.
type PingResult = probe.Result

func addPingCommand(parent *cobra.Command) *cobra.Command {
	cmd := clicky.AddNamedCommandWithContext("ping", parent, pingOptions{}, runPing)
	cmd.Use = "ping [host-or-url...]"
	cmd.Short = "Probe hosts and URLs"
	cmd.Long = "Probe explicit HTTP(S) URLs, or try both HTTPS and HTTP for each bare host.\n" +
		"When no arguments are supplied, targets are read one per line from stdin."
	return cmd
}

type pingOptions struct {
	Targets         []string          `args:"true" stdin:"true" help:"HTTP(S) URLs or bare hosts to probe"`
	Concurrency     int               `flag:"concurrency" default:"10" help:"Maximum concurrent probes"`
	Timeout         duration.Duration `flag:"timeout" default:"3s" help:"Timeout for each probe"`
	FollowRedirects bool              `flag:"follow-redirects" default:"true" help:"Follow HTTP redirects"`
}

func runPing(ctx context.Context, options pingOptions) ([]PingResult, error) {
	if options.Concurrency <= 0 {
		return nil, fmt.Errorf("concurrency must be greater than zero, got %d", options.Concurrency)
	}
	if options.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than zero, got %s", options.Timeout)
	}

	targets, err := pingTargets(options.Targets)
	if err != nil {
		return nil, err
	}
	results, failures := probeTargets(ctx, targets, options)
	if failures > 0 {
		return results, pingFailure(results)
	}
	return results, nil
}

type pingFailure []PingResult

func (f pingFailure) Error() string {
	failures := 0
	for _, result := range f {
		if !result.Up {
			failures++
		}
	}
	return fmt.Sprintf("%d of %d probes failed", failures, len(f))
}

func (f pingFailure) Pretty() api.Text {
	return api.Text{}.Add(api.NewTableFrom([]PingResult(f)))
}

func pingTargets(inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no hosts or URLs supplied")
	}
	var targets []string
	for i, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			return nil, fmt.Errorf("target %d is empty", i+1)
		}
		expanded, err := probe.Expand(input)
		if err != nil {
			return nil, err
		}
		targets = append(targets, expanded...)
	}
	return targets, nil
}

func probeTargets(ctx context.Context, targets []string, options pingOptions) ([]PingResult, int) {
	// WORKAROUND(clicky-worker-pool): SetGlobalMaxConcurrency updates the semaphore but does not grow Clicky's four initialized workers.
	// Correct fix: resize the global task worker pool when max concurrency changes.
	// Ref: gavel todo c7f7cd43-1a44-4127-8de9-105efb07304a
	//
	// Resizing a process-global semaphore is defensible here and nowhere else:
	// this command owns the process, runs once and exits. The inventory sweep in
	// internal/probes deliberately does not, because doing it from inside an HTTP
	// request would silently re-gate concurrent scans.
	clicky.SetGlobalMaxConcurrency(options.Concurrency)
	group := clicky.StartGroup[PingResult]("ping targets",
		task.WithKind("ping"),
		task.WithLabels(map[string]string{"targets": strconv.Itoa(len(targets))}),
		task.WithConcurrency(options.Concurrency))
	handles := make([]task.TypedTask[PingResult], 0, len(targets))
	for _, target := range targets {
		target := target
		handles = append(handles, group.Add(pingTaskName(target), func(taskCtx flanksourceContext.Context, t *task.Task) (PingResult, error) {
			probeCtx, cancel := context.WithCancel(taskCtx)
			stop := context.AfterFunc(ctx, cancel)
			defer func() {
				stop()
				cancel()
			}()
			result, err := probe.URL(probeCtx, target, probe.Options{
				Timeout:         time.Duration(options.Timeout),
				FollowRedirects: options.FollowRedirects,
			})
			t.SetDescription(describeProbe(result))
			// A target that did not answer is the answer, not a failed task —
			// finding them is what the command is for. Returning the error here
			// painted a run of a dead estate entirely red, and made ping and the
			// inventory sweep disagree about what "failed" means.
			if !result.Up {
				t.Warning()
				return result, nil
			}
			return result, err
		}, task.WithTaskTimeout(time.Duration(options.Timeout)), task.WithRetryConfig(task.RetryConfig{})))
	}
	group.WaitFor()

	results := make([]PingResult, len(handles))
	failures := 0
	for i, handle := range handles {
		result, err := handle.GetResult()
		if result.URL == "" {
			result.URL = targets[i]
		}
		if err != nil && result.Error == "" {
			result.Error = err.Error()
		}
		if !result.Up {
			failures++
		}
		results[i] = result
	}
	return results, failures
}

// describeProbe renders the one-line summary the task tree shows, in the same
// shape internal/probes uses so the two runs read alike.
//
// The kind leads the message: a tree of wrapped dial errors is a wall of text
// where the one word that says which team owns the problem is buried at the end.
func describeProbe(result PingResult) string {
	if result.Up {
		return fmt.Sprintf("%d in %dms", result.ResponseCode, result.ResponseTime.Milliseconds())
	}
	switch {
	case result.Failure != "" && result.Error != "":
		return fmt.Sprintf("%s: %s", result.Failure, result.Error)
	case result.Failure != "":
		return string(result.Failure)
	case result.Error != "":
		return result.Error
	}
	return "no answer"
}

func pingTaskName(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
