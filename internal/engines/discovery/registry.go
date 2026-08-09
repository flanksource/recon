// Package discovery holds the engines that find and characterise hosts. What
// they produce are observations that update the inventory, and they chain: one
// engine's output is the next one's input.
package discovery

import (
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/flanksource/recon/internal/engines"
)

// Kind is what a stage consumes or produces. Declaring both ends lets a chain be
// checked when it is built rather than when it is run.
type Kind string

const (
	// Zones are DNS zones to enumerate.
	Zones Kind = "zones"
	// Hosts are bare hostnames.
	Hosts Kind = "hosts"
	// Endpoints are host:port pairs.
	Endpoints Kind = "endpoints"
	// Origins are live scheme://host:port roots.
	Origins Kind = "origins"
	// Observations are normalised records that update a target.
	Observations Kind = "observations"
)

// Sourced reports whether the runtime supplies this kind from the inventory
// rather than an engine producing it. Origins are projected from the targets
// that already answered over HTTP, so a stage consuming them needs no
// predecessor. What seeds a chain is separate — see Chain.Seed.
func (k Kind) Sourced() bool { return k == Origins }

// Engine finds or characterises hosts.
type Engine interface {
	Spec() engines.Spec

	// Accepts and Emits describe where the engine sits in a chain.
	Accepts() Kind
	Emits() Kind

	// Args builds the command line for one run.
	Args(engines.Run) []string

	// Parse reads the engine's output, calling emit for each record. Streaming
	// rather than returning a slice: a discovery sweep over a large estate
	// should not have to be held in memory before anything is written.
	Parse(r io.Reader, emit func(Record) error) error
}

// Record is one observation. Host is required; the rest is whatever the engine
// reported, normalised later.
type Record struct {
	Host string
	// Fields is the raw normalised record. It is deliberately untyped here:
	// turning it into the target's machine-owned sections is internal/observe's
	// job, not the engine's.
	Fields map[string]any
}

var (
	mu       sync.RWMutex
	registry = map[string]Engine{}
)

// Register adds an engine. It panics on a bad spec or a duplicate name: both are
// programming errors that must fail at startup, not mid-scan.
func Register(engine Engine) {
	spec := engine.Spec()
	if err := spec.Validate(); err != nil {
		panic(fmt.Sprintf("discovery engine: %v", err))
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[spec.Name]; exists {
		panic(fmt.Sprintf("discovery engine %s registered twice", spec.Name))
	}
	registry[spec.Name] = engine
}

// Get returns one engine.
func Get(name string) (Engine, error) {
	mu.RLock()
	defer mu.RUnlock()
	engine, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown discovery engine: %s", name)
	}
	return engine, nil
}

// All returns every registered engine, ordered by name.
func All() []Engine {
	mu.RLock()
	defer mu.RUnlock()

	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Engine, 0, len(names))
	for _, name := range names {
		out = append(out, registry[name])
	}
	return out
}

// Specs returns every registered spec, ordered by name.
func Specs() []engines.Spec {
	all := All()
	specs := make([]engines.Spec, 0, len(all))
	for _, engine := range all {
		specs = append(specs, engine.Spec())
	}
	return specs
}
