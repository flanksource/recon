package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/api"
	"github.com/flanksource/clicky/task"
	flanksourceContext "github.com/flanksource/commons/context"
	"github.com/flanksource/commons/duration"
	"github.com/spf13/cobra"
)

const (
	defaultPingConcurrency = 10
	defaultPingTimeout     = 3 * time.Second
)

// PingResult is the result of probing one URL.
type PingResult struct {
	Up            bool          `json:"up"`
	URL           string        `json:"url"`
	FinalURL      string        `json:"final_url,omitempty"`
	IP            string        `json:"ip,omitempty"`
	TLSCN         string        `json:"tls_cn,omitempty"`
	ResponseCode  int           `json:"response_code,omitempty"`
	ContentType   string        `json:"content_type,omitempty"`
	ContentLength *int64        `json:"content_length,omitempty"`
	ResponseTime  time.Duration `json:"response_time"`
	ResponseSize  int64         `json:"response_size,omitempty"`
	Error         string        `json:"error,omitempty"`
}

var _ api.TableProvider = PingResult{}

func (PingResult) Columns() []api.ColumnDef {
	return []api.ColumnDef{
		api.Column("up").Label("Up").Build(),
		api.Column("url").Label("URL").Build(),
		api.Column("final_url").Label("Final URL").Build(),
		api.Column("ip").Label("IP").Build(),
		api.Column("tls_cn").Label("TLS CN").Build(),
		api.Column("response_code").Label("Response Code").Build(),
		api.Column("content_type").Label("Content Type").Build(),
		api.Column("content_length").Label("Content Length").Build(),
		api.Column("response_time").Label("Response Time").Build(),
		api.Column("response_size").Label("Response Size").Build(),
		api.Column("error").Label("Error").Build(),
	}
}

func (r PingResult) Row() map[string]any {
	row := map[string]any{
		"up":            r.Up,
		"url":           r.URL,
		"final_url":     r.FinalURL,
		"ip":            r.IP,
		"tls_cn":        r.TLSCN,
		"response_code": r.ResponseCode,
		"content_type":  r.ContentType,
		"response_time": clicky.Human(r.ResponseTime),
		"error":         r.Error,
	}
	if r.ContentLength != nil {
		row["content_length"] = api.HumanizeBytes(*r.ContentLength)
	} else {
		row["content_length"] = nil
	}
	if r.ResponseCode > 0 {
		row["response_size"] = api.HumanizeBytes(r.ResponseSize)
	} else {
		row["response_size"] = nil
	}
	return row
}

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
		expanded, err := expandPingTarget(input)
		if err != nil {
			return nil, err
		}
		targets = append(targets, expanded...)
	}
	return targets, nil
}

func expandPingTarget(input string) ([]string, error) {
	if strings.Contains(input, "://") {
		target, err := validatePingURL(input)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", input, err)
		}
		return []string{target}, nil
	}

	targets := make([]string, 0, 2)
	for _, scheme := range []string{"https", "http"} {
		target, err := validatePingURL(scheme + "://" + input)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", input, err)
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func validatePingURL(input string) (string, error) {
	parsed, err := url.Parse(input)
	if err != nil {
		return "", err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URL userinfo is not supported")
	}
	return parsed.String(), nil
}

func probeTargets(ctx context.Context, targets []string, options pingOptions) ([]PingResult, int) {
	// WORKAROUND(clicky-worker-pool): SetGlobalMaxConcurrency updates the semaphore but does not grow Clicky's four initialized workers.
	// Correct fix: resize the global task worker pool when max concurrency changes.
	// Ref: gavel todo c7f7cd43-1a44-4127-8de9-105efb07304a
	clicky.SetGlobalMaxConcurrency(options.Concurrency)
	group := clicky.StartGroup[PingResult]("ping targets", task.WithKind("ping"), task.WithConcurrency(options.Concurrency))
	handles := make([]task.TypedTask[PingResult], 0, len(targets))
	for _, target := range targets {
		target := target
		handles = append(handles, group.Add(pingTaskName(target), func(taskCtx flanksourceContext.Context, _ *task.Task) (PingResult, error) {
			probeCtx, cancel := context.WithCancel(taskCtx)
			stop := context.AfterFunc(ctx, cancel)
			defer func() {
				stop()
				cancel()
			}()
			return probeURL(probeCtx, target, pingProbeOptions{
				Timeout:         time.Duration(options.Timeout),
				FollowRedirects: options.FollowRedirects,
			})
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

func pingTaskName(target string) string {
	parsed, err := url.Parse(target)
	if err != nil {
		return target
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}
