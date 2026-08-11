package entities

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/discovery"
	"github.com/flanksource/recon/internal/scan"
	"github.com/flanksource/recon/internal/store"
)

// Runtimes are what the actions drive. They are optional so the entity routes
// can be served without them — a read-only deployment has no reason to be able
// to start a scan.
type Runtimes struct {
	Scans     *scan.Runtime
	Discovery *discovery.Runner
}

// scanFlags are the run-only choices a scan takes. They are not a profile: the
// profile stays what it is, and the effective configuration is recorded on the
// run.
type scanFlags struct {
	Engine  string `flag:"engine" help:"Scan engine to run" default:"nuclei"`
	Profile string `flag:"profile" help:"Stored scan profile for that engine" default:"safe"`
	// Repeatable, and one per engine: pre-scan discovery runs several engines,
	// so a bare name sets the default for all of them and `engine=name` picks a
	// different profile for one.
	DiscoveryProfiles []string `flag:"discovery-profile" help:"Discovery profile used before scanning: a name for every engine, or engine=name; repeatable"`
	// The pre-scan sweep is part of the run, so what it does is choosable here
	// too — otherwise a custom scan can only customise half of what it does.
	DiscoveryEngines  []string `flag:"discovery-engine" help:"Discovery engine to sweep with before scanning; repeatable. Empty runs the ones the sweep needs"`
	DiscoveryOverride string   `flag:"discovery-override" help:"Run-only discovery configuration as JSON keyed by engine, e.g. {\"naabu\":{\"top-ports\":\"full\"}}; not saved to the profile"`
	Override          string   `flag:"override" help:"Run-only scan configuration as JSON, e.g. {\"rate-limit\":50}; not saved to the profile"`
	Confirm           bool     `flag:"confirm" help:"Acknowledge an intrusive scan of production, public or unclassified hosts"`
	// Wait is on by default so a CLI run reports what it found. Over HTTP the
	// caller passes wait=false and watches /api/scan/events instead, because a
	// scan can take longer than any sensible request timeout.
	Wait bool `flag:"wait" help:"Block until the scan finishes and report the result" default:"true"`
}

func (scanFlags) ClickyActionFlags() {}

// discoverFlags choose the profile each participating engine runs with: a bare
// name applies to all of them, `engine=name` overrides one.
// EngineProfiles rather than Profiles: runTarget already carries a --profiles
// filter over the inventory, and the two are embedded side by side.
type discoverFlags struct {
	EngineProfiles []string `flag:"profile" help:"Stored discovery profile: a name for every engine, or engine=name; repeatable"`
	// Engines rather than a chain name: the chain says what a sweep starts from,
	// and this says which tools it drives on the way. Empty keeps the set the
	// chain needs, which is what a sweep ran before either was choosable.
	Engines  []string `flag:"engine" help:"Discovery engine to run; repeatable. Empty runs the ones the sweep needs"`
	Override string   `flag:"override" help:"Run-only configuration as JSON keyed by engine, e.g. {\"naabu\":{\"top-ports\":\"full\"}}; not saved to the profile"`
}

func (discoverFlags) ClickyActionFlags() {}

type scanRunOpts struct {
	runTarget
	scanFlags
}

func (scanRunOpts) ClickyActionFlags() {}

type discoverRunOpts struct {
	runTarget
	discoverFlags
}

func (discoverRunOpts) ClickyActionFlags() {}

// scanSelection starts a scan against everything the selector matches.
func (r *Registry) scanSelection(ctx context.Context, opts scanRunOpts) (api.Scan, error) {
	if r.Runtimes.Scans == nil {
		return api.Scan{}, fmt.Errorf("this build cannot start scans")
	}
	if r.Runtimes.Discovery == nil {
		return api.Scan{}, fmt.Errorf("this build cannot run discovery before scanning")
	}

	target, err := opts.resolve()
	if err != nil {
		return api.Scan{}, err
	}

	// Decoded before the sweep starts: a malformed override should cost nothing,
	// and finding out after discovery has already probed the estate would mean
	// paying for the traffic twice.
	sweepOverrides, err := discoveryOverrides(opts.DiscoveryOverride)
	if err != nil {
		return api.Scan{}, err
	}
	scanConfig, err := scanOverrides(opts.Override)
	if err != nil {
		return api.Scan{}, err
	}

	discoveryOpts := discovery.Options{
		Profiles:  opts.DiscoveryProfiles,
		Engines:   opts.DiscoveryEngines,
		Overrides: sweepOverrides,
	}
	scanSelector := target.Inventory
	if target.explicit() {
		discoveryOpts.Explicit = true
		discoveryOpts.Hosts = target.Hosts
		discoveryOpts.Domains = target.Domains
		discoveryOpts.CIDRs = target.CIDRs
	} else {
		discoveryOpts.Hosts, err = r.inventoryHosts(ctx, target.Inventory)
		if err != nil {
			return api.Scan{}, err
		}
		if len(discoveryOpts.Hosts) == 0 {
			return api.Scan{}, fmt.Errorf("no targets match %s: nothing to discover or scan", target.Inventory.Describe())
		}
		discoveryOpts.Input, err = target.Inventory.Map()
		if err != nil {
			return api.Scan{}, err
		}
	}

	sweep, err := r.Runtimes.Discovery.Run(ctx, discoveryOpts)
	if err != nil {
		return api.Scan{}, fmt.Errorf("pre-scan discovery: %w", err)
	}
	if target.explicit() {
		scanSelector, err = scanSelectorFromDiscovery(discoveredHostNames(sweep.Hosts))
		if err != nil {
			return api.Scan{}, err
		}
	}

	started, err := r.Runtimes.Scans.Start(ctx, scan.Request{
		Engine:    opts.Engine,
		Profile:   opts.Profile,
		Selector:  scanSelector,
		Overrides: scanConfig,
		Confirmed: opts.Confirm,
	})
	if err != nil || !opts.Wait {
		return started, err
	}
	// The scan supervises itself in a goroutine, so returning here would end the
	// process and take the run with it, leaving the row stuck at "running".
	return r.Runtimes.Scans.Wait(ctx, started.ID)
}

// discoverSelection re-probes everything the selector matches.
func (r *Registry) discoverSelection(ctx context.Context, opts discoverRunOpts) (api.Discover, error) {
	if r.Runtimes.Discovery == nil {
		return api.Discover{}, fmt.Errorf("this build cannot run discovery")
	}

	target, err := opts.resolve()
	if err != nil {
		return api.Discover{}, err
	}
	overrides, err := discoveryOverrides(opts.Override)
	if err != nil {
		return api.Discover{}, err
	}
	options := discovery.Options{
		Profiles:  opts.EngineProfiles,
		Engines:   opts.Engines,
		Overrides: overrides,
	}
	if target.explicit() {
		options.Explicit = true
		options.Hosts = target.Hosts
		options.Domains = target.Domains
		options.CIDRs = target.CIDRs
	} else if !target.Inventory.Empty() {
		options.Hosts, err = r.inventoryHosts(ctx, target.Inventory)
		if err != nil {
			return api.Discover{}, err
		}
		if len(options.Hosts) == 0 {
			return api.Discover{}, fmt.Errorf("no targets match %s: nothing to re-probe", target.Inventory.Describe())
		}
		options.Input, err = target.Inventory.Map()
		if err != nil {
			return api.Discover{}, err
		}
	}
	return r.Runtimes.Discovery.Run(ctx, options)
}

func (r *Registry) inventoryHosts(ctx context.Context, opts store.TargetOpts) ([]string, error) {
	st, err := r.store()
	if err != nil {
		return nil, err
	}
	targets, err := st.ListTargets(ctx, opts)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(targets))
	for _, target := range targets {
		hosts = append(hosts, target.Host)
	}
	return hosts, nil
}

func discoveredHostNames(hosts []api.DiscoveredHost) []string {
	names := make([]string, 0, len(hosts))
	for _, host := range hosts {
		names = append(names, host.Host)
	}
	return uniqueStrings(names)
}

func scanSelectorFromDiscovery(hosts []string) (store.TargetOpts, error) {
	hosts = uniqueStrings(hosts)
	if len(hosts) == 0 {
		return store.TargetOpts{}, fmt.Errorf("explicit discovery found no targets to scan")
	}
	return store.TargetOpts{Hosts: hosts}, nil
}

// Preview resolves a selector to the endpoints a scan would contact, without
// starting one.
//
// This exists to be looked at before a run: "which endpoints does this hit" has
// to be answerable in advance, or an intrusive scan can surprise someone.
func (r *Registry) Preview(ctx context.Context, opts store.TargetOpts) (Selection, error) {
	st, err := r.store()
	if err != nil {
		return Selection{}, err
	}

	endpoints, err := st.Endpoints(ctx, opts)
	if err != nil {
		return Selection{}, err
	}

	risky := store.Risky(endpoints)
	return Selection{
		Selector:  opts.Describe(),
		Endpoints: endpoints,
		Hosts:     store.Hosts(endpoints),
		Risky:     store.Hosts(risky),
	}, nil
}

// Selection is what a selector resolves to.
type Selection struct {
	Selector  string           `json:"selector"`
	Endpoints []store.Endpoint `json:"endpoints"`
	Hosts     []string         `json:"hosts"`

	// Risky names the hosts an intrusive scan would need confirming. Naming
	// them is the point: a prompt that says "3 production hosts" without saying
	// which is not one anyone can answer.
	Risky []string `json:"risky"`
}

// GetID identifies a preview by what it selected.
func (s Selection) GetID() string { return s.Selector }

// GetName describes the selection.
func (s Selection) GetName() string {
	return fmt.Sprintf("%s → %s endpoint(s) on %s host(s)",
		s.Selector, strconv.Itoa(len(s.Endpoints)), strconv.Itoa(len(s.Hosts)))
}

// String renders the selection for a confirmation prompt.
func (s Selection) String() string {
	if len(s.Risky) == 0 {
		return s.GetName()
	}
	return s.GetName() + ", including " + strings.Join(s.Risky, ", ")
}
