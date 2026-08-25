// Package scan holds the engines that test endpoints and report findings. Unlike
// discovery they do not chain: a scan runs against a fixed endpoint list
// resolved from the inventory, and what it produces is findings, not inventory
// state.
package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/mute"
)

// Engine tests endpoints and reports findings.
type Engine interface {
	Spec() engines.Spec

	// Risk judges whether this configuration sends traffic that could disrupt
	// the target. The runtime turns an intrusive verdict into a confirmation
	// gate; the engine decides what intrusive means for itself.
	Risk(config map[string]any) engines.Risk

	// Run executes one scan, reporting to sink as the scan progresses rather
	// than at the end: a scan takes minutes, and findings the UI only learns
	// about on completion are findings nobody can act on while it runs.
	//
	// Cancellation is the context. Returning nil means the engine ran to
	// completion — not that it found nothing.
	Run(ctx context.Context, run engines.Run, sink Sink) error
}

// Catalogue is implemented by engines that can say which templates a
// configuration selects before it runs.
//
// Optional, like Progress was: it is answerable for a template-driven scanner
// and meaningless for one whose checks are compiled in. An engine that cannot
// answer is not asked, and the UI shows no preview rather than a wrong one.
type Catalogue interface {
	// Templates lists everything the engine could run, unfiltered.
	Templates() ([]api.Template, error)

	// Preview reports what one configuration selects.
	Preview(config map[string]any) (api.TemplatePreview, error)

	// Corpus describes the installed catalogue without loading it into API
	// values. It reports its own failure rather than returning an error, because
	// "the templates are missing" is the answer an engine listing needs to show,
	// not a reason to fail the listing.
	Corpus() api.EngineTemplates
}

// PushdownRequest is what an engine is offered before a run starts.
type PushdownRequest struct {
	// Config is the effective configuration, modified in place. Appending to
	// the engine's own exclusion options here — rather than translating them at
	// execution time — is what keeps a preview, a rendered command line and the
	// run itself reading the same thing.
	Config map[string]any

	// WorkDir is the run's scratch directory, for an engine whose exclusions
	// live in a file rather than in a flag.
	WorkDir string

	// Rules are the rules in force, already narrowed to this engine.
	Rules []mute.Rule
}

// Pushdown is what an engine took on.
type Pushdown struct {
	// Plan names the rules the engine will enforce itself. Everything absent
	// from it is applied to the results instead.
	Plan mute.Plan

	// File is a generated input the engine needs on disk, empty when it
	// expressed everything through configuration.
	File string
}

// Muter is implemented by an engine that can decline to run a check.
//
// Optional, like Catalogue: an engine that cannot express an exclusion is not
// asked, and its rules are applied to the results instead. Not implementing it
// is the honest answer — a stub that accepted rules and quietly enforced none
// would read as a capability.
//
// An engine takes on only what it can express exactly. Its exclusions are a
// union while a rule's dimensions are an intersection, so a rule it cannot
// express in one option must be left alone rather than approximated: an
// approximation suppresses findings the rule does not cover, and since the
// checks never run, nothing is left to notice. mute.Rule.Pushable applies that
// test so every engine answers it the same way.
type Muter interface {
	Pushdown(PushdownRequest) (Pushdown, error)
}

// Sink receives everything a run produces.
//
// It replaces reading an engine's stdout: nuclei is linked in, so findings
// arrive as values and progress arrives as counters. There is no stdout/stderr
// distinction here because in-process there is no such thing — the runtime
// decides which stream to attribute engine output to.
type Sink interface {
	// Finding records one finding. An error aborts the run.
	Finding(api.Finding) error

	// Resource records one subject the run examined, whatever the verdict.
	//
	// Called for the checks that passed as well as the ones that failed, which
	// is the only way the estate becomes visible: a compliance scan of two GCP
	// projects reports 190 verdicts naming 94 resources, and recording only the
	// 49 failures left half of them with no trace anywhere in recon.
	//
	// Idempotent by natural key. An engine that meets the same resource in fifty
	// checks reports it fifty times and the runtime keeps one, unioning the
	// verdicts each call carried. An error aborts the run, matching Finding.
	Resource(api.Resource) error

	// Stats reports progress. Called often; the last call wins.
	Stats(api.ScanStats)

	// Log records the engine's own log output, verbatim.
	Log(text string)
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
		panic(fmt.Sprintf("scan engine: %v", err))
	}

	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[spec.Name]; exists {
		panic(fmt.Sprintf("scan engine %s registered twice", spec.Name))
	}
	registry[spec.Name] = engine
}

// Get returns one engine.
func Get(name string) (Engine, error) {
	mu.RLock()
	defer mu.RUnlock()
	engine, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown scan engine: %s", name)
	}
	return engine, nil
}

// ForProvider returns the one engine that declares context options for a
// provider.
//
// A provider-context target names a provider, not an engine: an operator adds
// "this container image" or "this GCP project" and the engine that can scan it
// follows from that. Resolving it here rather than assuming one engine is what
// lets a second provider-backed engine exist at all.
//
// Two engines claiming one provider is a wiring error, not a preference between
// them — the target would validate against whichever won a map iteration — so it
// is reported rather than resolved.
func ForProvider(provider string) (Engine, error) {
	var found []Engine
	for _, engine := range All() {
		options := engine.Spec().Options
		if options.Discriminator != "provider" {
			continue
		}
		for _, variant := range options.Variants {
			if variant.ID == provider && variant.ContextSchema != nil {
				found = append(found, engine)
				break
			}
		}
	}

	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, fmt.Errorf("no scan engine defines context options for provider %q", provider)
	default:
		names := make([]string, 0, len(found))
		for _, engine := range found {
			names = append(names, engine.Spec().Name)
		}
		return nil, fmt.Errorf("scan engines %s both define context options for provider %q",
			strings.Join(names, " and "), provider)
	}
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
