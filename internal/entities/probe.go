package entities

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/flanksource/clicky"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/observe"
	"github.com/flanksource/recon/internal/probe"
)

const (
	defaultProbeConcurrency = 10
	defaultProbeTimeout     = 5 * time.Second
)

// AddProbeCommand registers the liveness sweep on the command tree.
//
// A command rather than an entity because there is no probes table to list or
// address: the result of a probe is the target it updated. It is deliberately
// not marked local-only, so the same operation is served over HTTP — which is
// safe here and not for `ping`, because this one can only reach the inventory.
func (r *Registry) AddProbeCommand(parent *cobra.Command) *cobra.Command {
	cmd := clicky.AddNamedCommandWithContext("probe", parent, probeRunOpts{}, r.ProbeTargets)
	cmd.Short = "Probe inventory targets and refresh their liveness"
	cmd.Long = "Re-probes the hosts a selector matches over HTTPS and HTTP, and records what\n" +
		"answered — liveness, status code, response time and address — without running a\n" +
		"discovery engine. Technology, TLS and open ports are left as discovery found them."
	return cmd
}

// probeFlags are the run-only choices a liveness sweep takes.
type probeFlags struct {
	Timeout         string `flag:"timeout" help:"Timeout for each probe, such as 5s" default:"5s"`
	Concurrency     int    `flag:"concurrency" help:"Maximum concurrent probes" default:"10"`
	FollowRedirects bool   `flag:"follow-redirects" help:"Follow HTTP redirects" default:"true"`
}

func (probeFlags) ClickyActionFlags() {}

type probeRunOpts struct {
	runTarget
	probeFlags
}

func (probeRunOpts) ClickyActionFlags() {}

// ProbeTargets re-probes inventory targets and records what answered.
//
// Only the inventory: unlike `reconctl ping`, this takes a selector rather than
// a URL, so nothing here can be pointed at an arbitrary address. That is what
// makes it safe to serve over HTTP, where a free-form prober would be a way to
// reach anything the server can.
func (r *Registry) ProbeTargets(ctx context.Context, opts probeRunOpts) (api.ProbeRun, error) {
	st, err := r.store()
	if err != nil {
		return api.ProbeRun{}, err
	}

	target, err := opts.resolve()
	if err != nil {
		return api.ProbeRun{}, err
	}
	if target.explicit() && (len(target.Domains) > 0 || len(target.CIDRs) > 0) {
		return api.ProbeRun{}, fmt.Errorf(
			"a probe refreshes hosts already in the inventory: use --host, or discover the domain or network first")
	}

	hosts := target.Hosts
	if len(hosts) == 0 {
		hosts, err = r.inventoryHosts(ctx, target.Inventory)
		if err != nil {
			return api.ProbeRun{}, err
		}
	}
	hosts = uniqueStrings(hosts)
	if len(hosts) == 0 {
		return api.ProbeRun{}, fmt.Errorf("no targets match %s: nothing to probe", target.Inventory.Describe())
	}

	options, err := opts.probeOptions()
	if err != nil {
		return api.ProbeRun{}, err
	}

	started := time.Now()
	results := probeHosts(ctx, hosts, options, opts.concurrency())
	run := api.ProbeRun{
		RanAt:   started.Format(time.RFC3339),
		Results: results,
	}

	timestamp := started.Format(time.RFC3339Nano)
	var failures []error
	for _, result := range results {
		if result.Up {
			run.Live++
		}
		stored, err := st.GetTarget(ctx, result.Host)
		if err != nil {
			// A host named explicitly but never inventoried has no curated record
			// to update, and inventing one is discovery's job, not a refresh's.
			failures = append(failures, fmt.Errorf("%s: %w", result.Host, err))
			continue
		}
		stored, err = observe.ApplyProbe(stored, observation(result), timestamp)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", result.Host, err))
			continue
		}
		if err := st.SaveTarget(ctx, stored); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", result.Host, err))
			continue
		}
		run.Updated++
	}
	run.DurationMs = int(time.Since(started).Milliseconds())

	if len(failures) > 0 {
		return run, fmt.Errorf("%d of %d probes could not be recorded: %w",
			len(failures), len(results), failures[0])
	}
	return run, nil
}

func (o probeRunOpts) concurrency() int {
	if o.Concurrency <= 0 {
		return defaultProbeConcurrency
	}
	return o.Concurrency
}

func (o probeRunOpts) probeOptions() (probe.Options, error) {
	timeout := defaultProbeTimeout
	if o.Timeout != "" {
		parsed, err := time.ParseDuration(o.Timeout)
		if err != nil {
			return probe.Options{}, fmt.Errorf("invalid --timeout %q: %w", o.Timeout, err)
		}
		if parsed <= 0 {
			return probe.Options{}, fmt.Errorf("--timeout must be greater than zero, got %s", o.Timeout)
		}
		timeout = parsed
	}
	return probe.Options{Timeout: timeout, FollowRedirects: o.FollowRedirects}, nil
}

// probeHosts probes every host concurrently, keeping the best answer for each.
//
// A bare host is tried over HTTPS and HTTP, and the first scheme that answers is
// the one recorded: a host that redirects HTTP to HTTPS is up, and reporting the
// HTTP leg's redirect as its status would be a worse description of it.
func probeHosts(ctx context.Context, hosts []string, options probe.Options, concurrency int) []api.ProbeResult {
	results := make([]api.ProbeResult, len(hosts))
	slots := make(chan struct{}, concurrency)
	var wait sync.WaitGroup

	for i, host := range hosts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			results[i] = probeHost(ctx, host, options)
		}()
	}
	wait.Wait()
	return results
}

func probeHost(ctx context.Context, host string, options probe.Options) api.ProbeResult {
	targets, err := probe.Expand(host)
	if err != nil {
		return api.ProbeResult{Host: host, Error: err.Error()}
	}

	var last api.ProbeResult
	for _, target := range targets {
		result, err := probe.URL(ctx, target, options)
		converted := api.ProbeResult{
			Host:           host,
			URL:            result.URL,
			Up:             result.Up,
			StatusCode:     result.ResponseCode,
			ResponseTimeMs: result.ResponseTime.Milliseconds(),
			IP:             result.IP,
			ContentType:    result.ContentType,
		}
		if err != nil {
			converted.Error = result.Error
			if converted.Error == "" {
				converted.Error = err.Error()
			}
		}
		if converted.Up {
			return converted
		}
		last = converted
	}
	return last
}

func observation(result api.ProbeResult) observe.Probe {
	found := observe.Probe{
		Host:         result.Host,
		URL:          result.URL,
		IP:           result.IP,
		StatusCode:   result.StatusCode,
		ContentType:  result.ContentType,
		ResponseTime: time.Duration(result.ResponseTimeMs) * time.Millisecond,
		Failed:       !result.Up,
		Error:        result.Error,
	}
	found.Scheme, found.Port = schemeAndPort(result.URL)
	return found
}

// schemeAndPort reads the endpoint a probe actually reached, defaulting the
// port to the scheme's when the URL leaves it implicit.
func schemeAndPort(rawURL string) (string, int) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return "", 0
	}
	if named := parsed.Port(); named != "" {
		port, err := strconv.Atoi(named)
		if err != nil {
			return parsed.Scheme, 0
		}
		return parsed.Scheme, port
	}
	if parsed.Scheme == "https" {
		return parsed.Scheme, 443
	}
	return parsed.Scheme, 80
}
