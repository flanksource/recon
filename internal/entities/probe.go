package entities

import (
	"context"
	"fmt"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/probes"
)

const (
	defaultProbeConcurrency = 10
	defaultProbeTimeout     = 5 * time.Second
)

// probeFlags are the run-only choices a liveness sweep takes.
type probeFlags struct {
	Timeout         string `flag:"timeout" help:"Timeout for each probe, such as 5s" default:"5s"`
	Concurrency     int    `flag:"concurrency" help:"Maximum concurrent probes" default:"10"`
	FollowRedirects bool   `flag:"follow-redirects" help:"Follow HTTP redirects" default:"true"`
	// Wait is on by default so a CLI run reports what it found. Over HTTP the
	// caller passes wait=false and follows the run by id, because a sweep of the
	// estate outlasts any sensible request timeout.
	Wait bool `flag:"wait" help:"Block until every host has been probed and report the result" default:"true"`
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
	if r.Runtimes.Probes == nil {
		return api.ProbeRun{}, fmt.Errorf("this build cannot probe targets")
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

	timeout, err := opts.timeout()
	if err != nil {
		return api.ProbeRun{}, err
	}
	return r.Runtimes.Probes.Run(ctx, probes.Options{
		Selector:        target.Inventory,
		Hosts:           hosts,
		Timeout:         timeout,
		Concurrency:     opts.concurrency(),
		FollowRedirects: opts.FollowRedirects,
		Wait:            opts.Wait,
	})
}

func (o probeRunOpts) concurrency() int {
	if o.Concurrency <= 0 {
		return defaultProbeConcurrency
	}
	return o.Concurrency
}

func (o probeRunOpts) timeout() (time.Duration, error) {
	if o.Timeout == "" {
		return defaultProbeTimeout, nil
	}
	parsed, err := time.ParseDuration(o.Timeout)
	if err != nil {
		return 0, fmt.Errorf("invalid --timeout %q: %w", o.Timeout, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("--timeout must be greater than zero, got %s", o.Timeout)
	}
	return parsed, nil
}
