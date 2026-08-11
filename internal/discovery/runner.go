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
	// Profiles are the profile references the sweep runs with: a bare name every
	// engine uses, plus any number of engine=name overrides. Empty means the
	// default profile everywhere.
	Profiles []string

	// Engines chooses which discovery engines the sweep runs. Empty means the
	// ones the chain needs, which is what a sweep did before it was choosable.
	// The order is derived from what each engine consumes, so a caller supplies
	// a set rather than a pipeline.
	Engines []string

	// Overrides are run-only configuration tweaks, keyed by engine name and
	// layered over that engine's stored profile. They are not persisted: the
	// profile stays what it is, and a sweep that widened a port range once does
	// not widen every sweep after it.
	Overrides map[string]map[string]any

	Explicit bool
	Hosts    []string
	Domains  []string
	CIDRs    []string
	Input    map[string]any
}

// Run executes a sweep, merges the observations, and records what was seen.
//
// Concurrent calls share one run: the result is the same for everyone, and
// running two sweeps at once would double the traffic to third parties for no
// extra information.
func (r *Runner) Run(ctx context.Context, opts Options) (api.Discover, error) {
	if r.Store == nil {
		return api.Discover{}, fmt.Errorf("discovery runner requires a store")
	}
	if r.Provisioner == nil {
		return api.Discover{}, fmt.Errorf("discovery runner requires a provisioner")
	}
	set, err := ParseProfiles(opts.Profiles)
	if err != nil {
		return api.Discover{}, err
	}
	// Canonical references, so two spellings of the same profile selection share
	// one run rather than doubling the traffic to third parties. The engine
	// selection is canonicalised for the same reason, and rejecting an unknown
	// engine here means a bad name fails before any traffic is sent.
	opts.Profiles = set.Refs()
	if len(opts.Engines) > 0 {
		opts.Engines, err = OrderEngines(opts.Engines)
		if err != nil {
			return api.Discover{}, err
		}
	}

	key, err := runKey(opts)
	if err != nil {
		return api.Discover{}, err
	}
	result, err, _ := r.group.Do(key, func() (any, error) {
		bounded, cancel := context.WithTimeout(ctx, sweepDeadline)
		defer cancel()
		return r.run(bounded, opts, set)
	})
	if err != nil {
		return api.Discover{}, err
	}
	return result.(api.Discover), nil
}

func (r *Runner) run(ctx context.Context, opts Options, set ProfileSet) (api.Discover, error) {
	started := time.Now()
	mode, err := modeFor(opts)
	if err != nil {
		return api.Discover{}, err
	}
	// Which engines run depends on the chain unless the caller chose, so the set
	// is only resolved to names once that is known — a profile or configuration
	// override for an engine this sweep does not use is not an error, it simply
	// does not apply.
	engines := opts.Engines
	if len(engines) == 0 {
		engines = requiredEngines(mode, len(opts.Domains) > 0)
	}
	names := set.Resolve(engines)
	profiles, err := r.resolveProfiles(ctx, names, opts.Overrides)
	if err != nil {
		return api.Discover{}, err
	}

	input := discoveryInput(opts)
	row := models.Discovery{
		Chain: mode, Profiles: models.Wrap(&names), Input: models.Wrap(&input), RanAt: started,
	}
	if err := r.Store.CreateDiscovery(ctx, &row); err != nil {
		return api.Discover{}, err
	}

	tasks := newDiscoveryTaskGroup(row.ID, mode, set.String())
	stages, runErr := r.runStages(ctx, row.ID, mode, engines, opts, profiles, tasks)

	// A stage failing does not discard what earlier stages found: those hosts
	// are real, and dropping them would make a partial sweep look like an empty
	// estate.
	seen, saveErr := r.record(ctx, row.ID, stages)
	merged, mergeErr := r.merge(ctx, stages, started)

	row.DurationMs = int(time.Since(started).Milliseconds())
	row.Failed = runErr != nil || saveErr != nil || mergeErr != nil
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
			mode, runErr, len(seen), merged)
	}
	if saveErr != nil {
		return sweep, saveErr
	}
	return sweep, mergeErr
}

func (r *Runner) runStages(
	ctx context.Context,
	id, mode string,
	engines []string,
	opts Options,
	profiles map[string]map[string]any,
	tasks task.TypedGroup[Stage],
) ([]Stage, error) {
	run := func(chain Chain, input []string) ([]Stage, error) {
		return chain.Run(ctx, RunOptions{
			Root:        r.Root,
			Provisioner: r.Provisioner,
			Profiles:    profileLookup(profiles),
			Input:       input,
			ID:          id,
			Tasks:       tasks,
		})
	}

	prepared, err := runDiscoveryTask(ctx, tasks, "prepare discovery", func(ctx context.Context, t *task.Task) (Stage, error) {
		t.SetDescription("resolve discovery input")
		if mode != ChainExplicit {
			input, err := r.seed(ctx, mode, opts.Hosts)
			return Stage{Hosts: input}, err
		}
		return Stage{Hosts: distinctStrings(append(append(append([]string{}, opts.Hosts...), opts.Domains...), opts.CIDRs...))}, nil
	})
	if err != nil {
		return nil, err
	}

	if mode != ChainExplicit {
		chain, err := chainFor(mode, engines)
		if err != nil {
			return nil, err
		}
		return run(chain, prepared.Hosts)
	}

	// An explicit request can name domains, hosts and CIDRs at once, so the
	// selection runs as two chains: the stages that enumerate a zone, then the
	// stages that probe everything the caller named plus whatever that produced.
	enumerators, probers := seedsFromZones(engines)

	probeInput := prepared.Hosts
	var stages []Stage
	if len(opts.Domains) > 0 && len(enumerators) > 0 {
		enumerate, err := NewChain(ChainExplicit, enginediscovery.Zones, enumerators...)
		if err != nil {
			return nil, err
		}
		enumerated, err := run(enumerate, opts.Domains)
		stages = append(stages, enumerated...)
		if err != nil {
			return stages, err
		}
		if len(enumerated) > 0 {
			probeInput = append(probeInput, enumerated[len(enumerated)-1].Hosts...)
		}
	}
	probeInput = distinctStrings(probeInput)
	if len(probeInput) == 0 || len(probers) == 0 {
		return stages, nil
	}
	probe, err := NewChain(ChainExplicit, enginediscovery.Hosts, probers...)
	if err != nil {
		return stages, err
	}
	probed, err := run(probe, probeInput)
	return append(stages, probed...), err
}

// seed builds the first stage's input: the configured zones for a full sweep,
// the named hosts for a targeted one.
func (r *Runner) seed(ctx context.Context, mode string, selected []string) ([]string, error) {
	if mode == ChainTargeted {
		if len(selected) == 0 {
			return nil, fmt.Errorf("a targeted sweep needs hosts to probe")
		}
		return selected, nil
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

// chainFor builds a sweep out of the engines it will run. The seed is what the
// mode supplies: zones for a full sweep, hosts for a targeted one, which is what
// makes a targeted chain valid without an enumerating stage.
func chainFor(name string, engines []string) (Chain, error) {
	switch name {
	case ChainFull:
		return NewChain(ChainFull, enginediscovery.Zones, engines...)
	case ChainTargeted:
		// Skips enumeration: the hosts are already known, and this is the
		// rescan that refreshes what is recorded about them.
		return NewChain(ChainTargeted, enginediscovery.Hosts, engines...)
	default:
		return Chain{}, fmt.Errorf("unknown chain %q: expected one of %s",
			name, strings.Join(ChainNames(), ", "))
	}
}

func (r *Runner) resolveProfiles(
	ctx context.Context,
	names map[string]string,
	overrides map[string]map[string]any,
) (map[string]map[string]any, error) {
	profiles := make(map[string]map[string]any, len(names))
	for engine, name := range names {
		profile, err := r.Store.GetProfile(ctx, "discovery:"+engine+":"+name)
		if err != nil {
			return nil, fmt.Errorf("discovery profile %q for %s: %w", name, engine, err)
		}
		config := withOverrides(profile.Config, overrides[engine])
		// Only the overridden configuration is checked: it is the input this
		// request supplied, and a stored profile is validated where it is
		// written. An override the engine would reject must fail before the
		// sweep sends traffic, not once the tool exits non-zero.
		if len(overrides[engine]) > 0 {
			spec, err := enginediscovery.Get(engine)
			if err != nil {
				return nil, err
			}
			if err := spec.Spec().ValidateConfig(config); err != nil {
				return nil, fmt.Errorf("%s configuration: %w", engine, err)
			}
		}
		profiles[engine] = config
	}
	return profiles, nil
}

func profileLookup(profiles map[string]map[string]any) func(string) (map[string]any, error) {
	return func(engine string) (map[string]any, error) {
		profile, ok := profiles[engine]
		if !ok {
			return nil, fmt.Errorf("profile for discovery engine %s was not preflighted", engine)
		}
		return profile, nil
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
type hostFinding struct {
	Observations []map[string]any
	Ports        []int
	IP           string
}

func discoveryFindings(stages []Stage) map[string]hostFinding {
	findings := map[string]hostFinding{}
	for _, stage := range stages {
		if stage.Engine == nil {
			continue
		}
		for _, host := range stage.Hosts {
			if _, ok := findings[host]; !ok {
				findings[host] = hostFinding{}
			}
		}
		for _, record := range stage.Records {
			finding := findings[record.Host]
			switch stage.Engine.Emits() {
			case enginediscovery.Observations:
				finding.Observations = append(finding.Observations, record.Fields)
			case enginediscovery.Endpoints:
				if port, ok := record.Fields["port"].(int); ok {
					finding.Ports = append(finding.Ports, port)
				}
				if ip, ok := record.Fields["ip"].(string); ok && ip != "" {
					finding.IP = ip
				}
			}
			findings[record.Host] = finding
		}
	}
	for host, finding := range findings {
		finding.Ports = distinctInts(finding.Ports)
		findings[host] = finding
	}
	return findings
}

func distinctInts(values []int) []int {
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]int, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func portsAsAny(values []int) []any {
	result := make([]any, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

func (r *Runner) merge(ctx context.Context, stages []Stage, at time.Time) (int, error) {
	findings := discoveryFindings(stages)
	if len(findings) == 0 {
		return 0, nil
	}

	hosts := make([]string, 0, len(findings))
	for host := range findings {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	timestamp := at.Format(time.RFC3339Nano)
	updated := 0
	var failures []error

	for _, host := range hosts {
		target, err := r.Store.EnsureDiscoveredTarget(ctx, host)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", host, err))
			continue
		}

		finding := findings[host]
		if len(finding.Ports) > 0 {
			target, err = observe.ApplyEndpoints(target, observe.EndpointObservation{
				Host: host, IP: finding.IP, Ports: finding.Ports,
			}, timestamp)
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", host, err))
				continue
			}
		}

		if record := observe.PrimaryRecord(finding.Observations); record != nil {
			projected := observe.InventoryProjection(record)
			if len(finding.Ports) > 0 {
				projected["open_ports"] = portsAsAny(finding.Ports)
			}
			if _, ok := projected["host_ip"]; !ok && finding.IP != "" {
				projected["host_ip"] = finding.IP
			}
			target, err = observe.Apply(target, projected, timestamp)
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", host, err))
				continue
			}
		}
		if err := r.Store.SaveTarget(ctx, target); err != nil {
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
