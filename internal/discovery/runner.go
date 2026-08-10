package discovery

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/flanksource/clicky/task"
	"golang.org/x/sync/singleflight"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/observe"
	"github.com/flanksource/recon/internal/store"
)

// sweepDeadline bounds a whole sweep. Enumeration talks to third-party sources
// that can hang, and a run that never ends holds the singleflight slot against
// every later request.
const sweepDeadline = 220 * time.Second

// Runner executes discovery sweeps and merges what they see into the inventory.
type Runner struct {
	Store       *store.Store
	Provisioner *engines.Provisioner
	Root        string

	// SpecDirs are the manifest trees the static stage reads. Empty disables
	// that stage rather than defaulting to a path that may not be this repo's.
	SpecDirs []string

	// Resolver answers the DNS stage. Nil uses the system resolver.
	Resolver Resolver

	// group collapses concurrent sweeps onto one run: two browser tabs both
	// pressing Discover should not scan the estate twice.
	group singleflight.Group
}

// Options selects what a sweep does.
type Options struct {
	// Chain is "full" or "targeted".
	Chain string

	// Hosts seeds a targeted sweep. Ignored by a full one, which enumerates
	// from the configured zones instead.
	Hosts []string

	Task *task.Task
}

// Run executes a sweep, merges the observations, and records what was seen.
//
// Concurrent calls share one run: the result is the same for everyone, and
// running two sweeps at once would double the traffic to third parties for no
// extra information.
func (r *Runner) Run(ctx context.Context, opts Options) (api.Discover, error) {
	result, err, _ := r.group.Do(opts.Chain, func() (any, error) {
		bounded, cancel := context.WithTimeout(ctx, sweepDeadline)
		defer cancel()
		return r.run(bounded, opts)
	})
	if err != nil {
		return api.Discover{}, err
	}
	return result.(api.Discover), nil
}

func (r *Runner) run(ctx context.Context, opts Options) (api.Discover, error) {
	started := time.Now()

	input, err := r.seed(ctx, opts)
	if err != nil {
		return api.Discover{}, err
	}

	chain, err := r.chainFor(opts.Chain)
	if err != nil {
		return api.Discover{}, err
	}

	row := models.Discovery{Chain: opts.Chain, RanAt: started}
	if err := r.Store.CreateDiscovery(ctx, &row); err != nil {
		return api.Discover{}, err
	}

	stages, runErr := chain.Run(ctx, RunOptions{
		Root:        r.Root,
		Provisioner: r.Provisioner,
		Profiles:    r.profileFor(ctx),
		Input:       input,
		Task:        opts.Task,
		ID:          row.ID,
	})

	// A stage failing does not discard what earlier stages found: those hosts
	// are real, and dropping them would make a partial sweep look like an empty
	// estate.
	seen, saveErr := r.record(ctx, row.ID, stages)
	merged, mergeErr := r.merge(ctx, stages, started)

	row.DurationMs = int(time.Since(started).Milliseconds())
	row.Failed = runErr != nil
	if runErr != nil {
		text := runErr.Error()
		row.Error = &text
	} else if saveErr != nil {
		text := saveErr.Error()
		row.Error = &text
	} else if mergeErr != nil {
		text := mergeErr.Error()
		row.Error = &text
	}
	if err := r.Store.FinishDiscovery(ctx, row); err != nil {
		return api.Discover{}, err
	}

	sweep, err := r.Store.GetDiscovery(ctx, row.ID)
	if err != nil {
		return api.Discover{}, err
	}
	if runErr != nil {
		return sweep, fmt.Errorf("discovery chain %s: %w (%d host(s) recorded, %d target(s) updated)",
			opts.Chain, runErr, len(seen), merged)
	}
	if saveErr != nil {
		return sweep, saveErr
	}
	return sweep, mergeErr
}

// seed builds the first stage's input: the configured zones for a full sweep,
// the named hosts for a targeted one.
func (r *Runner) seed(ctx context.Context, opts Options) ([]string, error) {
	if opts.Chain == "targeted" {
		if len(opts.Hosts) == 0 {
			return nil, fmt.Errorf("a targeted sweep needs hosts to probe")
		}
		return opts.Hosts, nil
	}

	zones, err := r.Store.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	if len(zones) == 0 {
		return nil, fmt.Errorf(
			"no zones are configured, so there is nothing to enumerate: add one with `reconctl zone create zone=example.com`")
	}

	hosts := map[string]bool{}
	for _, zone := range zones {
		hosts[zone] = true
	}

	// The stages that are not engines contribute their hosts up front, so the
	// chain starts from everything already known about the estate.
	if len(r.SpecDirs) > 0 {
		found, err := StaticScrape{Dirs: r.SpecDirs, Zones: zones}.Run()
		if err != nil {
			return nil, err
		}
		for _, host := range found {
			hosts[host] = true
		}
	}

	resolver := r.Resolver
	if resolver == nil {
		resolver = SystemResolver()
	}
	dns, err := DiscoverDNS(ctx, resolver, zones)
	if err != nil {
		return nil, err
	}
	for _, host := range dns.Hosts {
		hosts[host] = true
	}

	seeded := make([]string, 0, len(hosts))
	for host := range hosts {
		seeded = append(seeded, host)
	}
	sort.Strings(seeded)
	return seeded, nil
}

func (r *Runner) chainFor(name string) (Chain, error) {
	switch name {
	case ChainFull:
		return NewChain(ChainFull, enginediscovery.Zones, "subfinder", "naabu", "httpx", "tlsx")
	case ChainTargeted:
		// Skips enumeration: the hosts are already known, and this is the
		// rescan that refreshes what is recorded about them.
		return NewChain(ChainTargeted, enginediscovery.Hosts, "naabu", "httpx", "tlsx")
	default:
		return Chain{}, fmt.Errorf("unknown chain %q: expected one of %s",
			name, strings.Join(ChainNames(), ", "))
	}
}

// profileFor resolves each engine's stored configuration.
func (r *Runner) profileFor(ctx context.Context) func(string) (map[string]any, error) {
	return func(engine string) (map[string]any, error) {
		profile, err := r.Store.GetProfile(ctx, "discovery:"+engine+":default")
		if err != nil {
			return nil, err
		}
		return profile.Config, nil
	}
}

// record writes what each engine saw, per host and per engine.
func (r *Runner) record(ctx context.Context, discoveryID string, stages []Stage) ([]string, error) {
	var rows []models.DiscoveryHost
	seen := map[string]bool{}

	for _, stage := range stages {
		if stage.Engine == nil {
			continue
		}
		name := stage.Engine.Spec().Name
		for _, host := range stage.Hosts {
			rows = append(rows, models.DiscoveryHost{
				DiscoveryID: discoveryID, Host: host, Engine: name,
				Live: stage.Engine.Emits() == enginediscovery.Observations,
			})
			seen[host] = true
		}
	}
	// Reported rather than swallowed: a sweep whose findings were not recorded
	// has not really run, and the caller decides what that means.
	saveErr := r.Store.SaveDiscoveryHosts(ctx, rows)

	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, saveErr
}

// merge folds the observation records into the inventory.
//
// Several engines can describe the same host, so the records are grouped and
// the best one picked before anything is written — applying them in arrival
// order would let a failed probe overwrite a successful one.
func (r *Runner) merge(ctx context.Context, stages []Stage, at time.Time) (int, error) {
	byHost := map[string][]map[string]any{}
	for _, stage := range stages {
		if stage.Engine == nil || stage.Engine.Emits() != enginediscovery.Observations {
			continue
		}
		for _, record := range stage.Records {
			byHost[record.Host] = append(byHost[record.Host], record.Fields)
		}
	}
	if len(byHost) == 0 {
		return 0, nil
	}

	hosts := make([]string, 0, len(byHost))
	for host := range byHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	timestamp := at.Format(time.RFC3339Nano)
	updated := 0
	var failures []error

	for _, host := range hosts {
		record := observe.PrimaryRecord(byHost[host])
		if record == nil {
			continue
		}

		target, err := r.Store.GetTarget(ctx, host)
		if err != nil {
			// A host discovery found but the inventory does not have is not an
			// error: it is the backlog, recorded as an unknown host above and
			// classified by a person, not by a sweep.
			continue
		}

		applied, err := observe.Apply(target, observe.InventoryProjection(record), timestamp)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", host, err))
			continue
		}
		if err := r.Store.SaveTarget(ctx, applied); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", host, err))
			continue
		}
		updated++
	}

	if len(failures) > 0 {
		return updated, fmt.Errorf("%d of %d observations could not be applied: %w",
			len(failures), len(hosts), failures[0])
	}
	return updated, nil
}
