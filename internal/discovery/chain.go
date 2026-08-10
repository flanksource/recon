package discovery

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/flanksource/clicky/task"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
)

// The two sweeps on offer. A full sweep enumerates from the configured zones;
// a targeted one re-probes hosts the caller already knows about.
const (
	ChainFull     = "full"
	ChainTargeted = "targeted"
	ChainExplicit = "explicit"
)

// ChainNames lists the sweeps a caller may ask for, so the filter control, the
// flag's help and the error a bad name produces cannot fall out of step.
func ChainNames() []string { return []string{ChainFull, ChainTargeted, ChainExplicit} }

// Chain is an ordered pipeline of discovery engines. Each stage consumes what
// the previous one emitted, which is checked when the chain is built rather
// than discovered when it runs.
type Chain struct {
	Name string

	// Seed is what the runtime feeds the first stage: zones for a full sweep,
	// hosts for a targeted one. It is what makes a targeted chain valid — its
	// first stage consumes hosts that no earlier stage produced because the
	// caller supplied them.
	Seed discovery.Kind

	Engines []discovery.Engine
}

// NewChain builds a chain and verifies the stages fit together.
func NewChain(name string, seed discovery.Kind, names ...string) (Chain, error) {
	chain := Chain{Name: name, Seed: seed}
	for _, engineName := range names {
		engine, err := discovery.Get(engineName)
		if err != nil {
			return Chain{}, err
		}
		chain.Engines = append(chain.Engines, engine)
	}
	if err := chain.Validate(); err != nil {
		return Chain{}, err
	}
	return chain, nil
}

// Validate checks that each stage is fed by something.
//
// A chain whose stages do not fit produces nothing and reports success, which
// is the worst way for discovery to fail — it looks like an estate with no
// hosts in it.
func (c Chain) Validate() error {
	if len(c.Engines) == 0 {
		return fmt.Errorf("chain %s has no stages", c.Name)
	}

	if c.Seed == "" {
		return fmt.Errorf("chain %s: no seed kind", c.Name)
	}

	// What the caller supplies counts as available: a targeted sweep starts from
	// hosts it was given, and demanding a stage produce them rejected the chain
	// outright.
	available := map[discovery.Kind]bool{c.Seed: true}
	for _, engine := range c.Engines {
		accepts := engine.Accepts()
		if !accepts.Sourced() && !available[accepts] {
			return fmt.Errorf(
				"chain %s: %s consumes %s, which no earlier stage produces",
				c.Name, engine.Spec().Name, accepts)
		}
		available[engine.Emits()] = true
	}
	return nil
}

// Stage is one engine's turn in a chain.
type Stage struct {
	Engine  discovery.Engine
	Records []discovery.Record

	// Hosts is what this stage contributed, in byte order.
	Hosts []string

	ExitCode int
	Err      error
	Command  []string
}

// RunOptions is what a chain needs to run.
type RunOptions struct {
	// Root is where per-run scratch directories are created.
	Root string

	// Provisioner resolves each engine's binary.
	Provisioner *engines.Provisioner

	// Profiles supplies the effective configuration for an engine. Returning an
	// error stops the chain: running an engine with no configuration would
	// silently use its own defaults rather than the ones on record.
	Profiles func(engine string) (map[string]any, error)

	// Input seeds the first stage — zones for a full sweep, hosts for a
	// targeted one.
	Input []string

	// Task carries cancellation and progress.
	Task *task.Task

	// ID names the run's scratch directory.
	ID string
}

// Run executes the chain, feeding each stage what the previous one emitted.
//
// Exit codes 0 and 3 are both success: several of these tools use 3 to mean
// "differences found", which is the normal outcome of a discovery sweep rather
// than a failure.
func (c Chain) Run(ctx context.Context, opts RunOptions) ([]Stage, error) {
	if opts.Provisioner == nil {
		return nil, fmt.Errorf("chain %s: no provisioner", c.Name)
	}
	if len(opts.Input) == 0 {
		return nil, fmt.Errorf("chain %s: nothing to start from", c.Name)
	}

	input := append([]string(nil), opts.Input...)
	var stages []Stage

	for index, engine := range c.Engines {
		spec := engine.Spec()

		if len(input) == 0 {
			// Not an error: an earlier stage legitimately found nothing. Record
			// the stage so the run shows where the chain stopped.
			stages = append(stages, Stage{Engine: engine})
			continue
		}

		stage, err := c.runStage(ctx, engine, input, opts)
		if err != nil {
			return stages, fmt.Errorf("chain %s: %s: %w", c.Name, spec.Name, err)
		}
		stages = append(stages, stage)

		// The next stage is fed by what this one emitted. An engine that emits
		// observations does not extend the host list — it describes hosts that
		// are already known — so the input carries through unchanged.
		if index < len(c.Engines)-1 && engine.Emits() != discovery.Observations {
			input, err = stageOutput(stage)
			if err != nil {
				return stages, fmt.Errorf("chain %s: %s output: %w", c.Name, spec.Name, err)
			}
		}
	}
	return stages, nil
}

func stageOutput(stage Stage) ([]string, error) {
	if stage.Engine.Emits() != discovery.Endpoints {
		return stage.Hosts, nil
	}

	values := make([]string, 0, len(stage.Records))
	for _, record := range stage.Records {
		value, _ := record.Fields["endpoint"].(string)
		if value == "" {
			value, _ = record.Fields["url"].(string)
		}
		if value == "" {
			return nil, fmt.Errorf("endpoint record for %s has neither endpoint nor url", record.Host)
		}
		values = append(values, value)
	}
	return distinctValues(values), nil
}

func distinctValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (c Chain) runStage(ctx context.Context, engine discovery.Engine, input []string, opts RunOptions) (Stage, error) {
	spec := engine.Spec()
	stage := Stage{Engine: engine}

	bin, err := opts.Provisioner.Resolve(spec)
	if err != nil {
		return stage, err
	}

	config := map[string]any{}
	if opts.Profiles != nil {
		config, err = opts.Profiles(spec.Name)
		if err != nil {
			return stage, err
		}
	}

	dir, err := engines.NewWorkDir(opts.Root, "discover", opts.ID+"-"+spec.Name)
	if err != nil {
		return stage, err
	}

	in, err := engines.WriteList(dir, "input.txt", input)
	if err != nil {
		return stage, err
	}

	run := engines.Run{
		Task: opts.Task, Bin: bin, WorkDir: dir, Config: config,
		In: in, Out: filepath.Join(dir, "output.jsonl"),
	}

	// The engines stream their records on stdout, so the parser reads the
	// process output directly rather than a file written afterwards.
	reader, writer := newPipe()
	invocation := &engines.Invocation{
		Bin: bin, Args: engine.Args(run), WorkDir: dir, Task: opts.Task, Stdout: writer,
	}
	defer invocation.Cleanup()

	parsed := make(chan error, 1)
	go func() {
		parsed <- engine.Parse(reader, func(record discovery.Record) error {
			stage.Records = append(stage.Records, record)
			return nil
		})
	}()

	result := invocation.Run(ctx)
	_ = writer.Close()
	parseErr := <-parsed

	stage.ExitCode = result.ExitCode
	stage.Command = result.Command
	stage.Err = result.Err

	if !successfulExit(result.ExitCode) {
		return stage, fmt.Errorf("exited %d: %w", result.ExitCode, result.Err)
	}
	if parseErr != nil {
		// The process succeeded, so the records collected before the bad line
		// are real. Report the damage without discarding them.
		stage.Err = parseErr
	}

	stage.Hosts = distinctHosts(stage.Records)
	return stage, nil
}

// successfulExit reports whether an exit code means the stage worked. 3 is
// "differences found", which several of these tools return on a normal run.
func successfulExit(code int) bool { return code == 0 || code == 3 }

func distinctHosts(records []discovery.Record) []string {
	seen := map[string]bool{}
	for _, record := range records {
		if host := strings.TrimSpace(record.Host); host != "" {
			seen[host] = true
		}
	}

	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

// newPipe returns an os.Pipe pair. Used rather than io.Pipe so the writer can
// be handed to a child process's stdout.
func newPipe() (*os.File, *os.File) {
	reader, writer, err := os.Pipe()
	if err != nil {
		panic(fmt.Sprintf("create pipe: %v", err))
	}
	return reader, writer
}
