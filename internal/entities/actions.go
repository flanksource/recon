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
	Engine           string `flag:"engine" help:"Scan engine to run" default:"nuclei"`
	Profile          string `flag:"profile" help:"Stored scan profile for that engine" default:"safe"`
	DiscoveryProfile string `flag:"discovery-profile" help:"Stored profile used by every discovery engine before scanning" default:"default"`
	Confirm          bool   `flag:"confirm" help:"Acknowledge an intrusive scan of production, public or unclassified hosts"`
	// Wait is on by default so a CLI run reports what it found. Over HTTP the
	// caller passes wait=false and watches /api/scan/events instead, because a
	// scan can take longer than any sensible request timeout.
	Wait bool `flag:"wait" help:"Block until the scan finishes and report the result" default:"true"`
}

func (scanFlags) ClickyActionFlags() {}

// discoverFlags choose the shared profile name for every participating engine.
type discoverFlags struct {
	Profile string `flag:"profile" help:"Stored profile used by every discovery engine" default:"default"`
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

	discoveryOpts := discovery.Options{Profile: opts.DiscoveryProfile}
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
		Confirmed: opts.Confirm,
	})
	if err != nil || !opts.Wait {
		return started, err
	}
	// The scan supervises itself in a goroutine, so returning here would end the
	// process and take the run with it, leaving the row stuck at "running".
	return r.Runtimes.Scans.Wait(ctx)
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
	options := discovery.Options{Profile: opts.Profile}
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
