package entities

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/entity"
	"github.com/spf13/cobra"

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
	Profile string `flag:"profile" help:"Stored profile for that engine" default:"safe"`
	Confirm bool   `flag:"confirm" help:"Acknowledge an intrusive scan of production, public or unclassified hosts"`
	// Wait is on by default so a CLI run reports what it found. Over HTTP the
	// caller passes wait=false and watches /api/scan/events instead, because a
	// scan can take longer than any sensible request timeout.
	Wait bool `flag:"wait" help:"Block until the scan finishes and report the result" default:"true"`
}

func (scanFlags) ClickyActionFlags() {}

// discoverFlags choose which sweep to run.
type discoverFlags struct {
	Chain string `flag:"chain" help:"full enumerates from the configured zones; targeted re-probes known hosts" default:"targeted"`
}

func (discoverFlags) ClickyActionFlags() {}

// registerActions adds the operations that do something rather than return
// something. They hang off the target entity because both are driven by a
// selector: "scan what this filter matches" is the whole point.
func (r *Registry) registerActions() {
	if r.Runtimes.Scans != nil {
		clicky.RegisterSubCommandFn("target", func(parent *cobra.Command) {
			command := entity.AddNamedCommandWithContext(
				"scan", parent, scanSelectorOpts{}, r.scanSelection)
			command.Short = "Scan every target the selector matches"
			command.Long = "Resolves the selector to endpoints and points one scan engine at them.\n" +
				"An intrusive profile against production, public or unclassified hosts is\n" +
				"refused unless --confirm is given."
		})
	}
	if r.Runtimes.Discovery != nil {
		clicky.RegisterSubCommandFn("target", func(parent *cobra.Command) {
			command := entity.AddNamedCommandWithContext(
				"discover", parent, discoverSelectorOpts{}, r.discoverSelection)
			command.Short = "Re-probe every target the selector matches"
			command.Long = "A targeted sweep refreshes what is recorded about hosts already in the\n" +
				"inventory. --chain full instead enumerates from the configured zones."
		})
	}
}

// scanSelectorOpts is the target selector plus the run-only choices, so
// `reconctl target scan --class non-prod --engine nuclei` is one command.
type scanSelectorOpts struct {
	store.TargetOpts
	scanFlags
}

// discoverSelectorOpts is the selector plus the chain choice.
type discoverSelectorOpts struct {
	store.TargetOpts
	discoverFlags
}

// scanSelection starts a scan against everything the selector matches.
func (r *Registry) scanSelection(ctx context.Context, opts scanSelectorOpts) (api.Scan, error) {
	if r.Runtimes.Scans == nil {
		return api.Scan{}, fmt.Errorf("this build cannot start scans")
	}
	started, err := r.Runtimes.Scans.Start(ctx, scan.Request{
		Engine:    opts.Engine,
		Profile:   opts.Profile,
		Selector:  opts.TargetOpts,
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
func (r *Registry) discoverSelection(ctx context.Context, opts discoverSelectorOpts) (api.Discover, error) {
	if r.Runtimes.Discovery == nil {
		return api.Discover{}, fmt.Errorf("this build cannot run discovery")
	}

	options := discovery.Options{Chain: opts.Chain}
	if opts.Chain == "targeted" {
		st, err := r.store()
		if err != nil {
			return api.Discover{}, err
		}
		targets, err := st.ListTargets(ctx, opts.TargetOpts)
		if err != nil {
			return api.Discover{}, err
		}
		for _, target := range targets {
			options.Hosts = append(options.Hosts, target.Host)
		}
		if len(options.Hosts) == 0 {
			return api.Discover{}, fmt.Errorf(
				"no targets match %s: nothing to re-probe", opts.TargetOpts.Describe())
		}
	}
	return r.Runtimes.Discovery.Run(ctx, options)
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
