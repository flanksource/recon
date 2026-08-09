package engines

import (
	"fmt"

	"github.com/flanksource/clicky/task"
)

// Run is everything one engine invocation needs. It stays deliberately small:
// nuclei's stats streaming, SARIF export and tag excludes are nuclei's business,
// not every engine's, and putting them here would make tlsx or katana implement
// fields that mean nothing to them.
type Run struct {
	// Task reports progress and carries cancellation.
	Task *task.Task

	// Bin is the resolved absolute path to the engine binary.
	Bin string

	// WorkDir is a per-run scratch directory, removed when the run ends. Inputs
	// the engine needs on disk are written here.
	WorkDir string

	// Config is the effective profile: the stored profile with any run-only
	// overrides already applied.
	Config map[string]any

	// In is the rendered input file — the host or endpoint list.
	In string

	// Out is where the engine should write its machine-readable output.
	Out string
}

// Flag reads a config value as a string.
func (r Run) Flag(key string) (string, bool) {
	value, ok := r.Config[key]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

// Bool reports whether a boolean option is set and true.
func (r Run) Bool(key string) bool {
	value, ok := r.Config[key]
	if !ok {
		return false
	}
	enabled, ok := value.(bool)
	return ok && enabled
}

// Risk describes whether a scan engine's configuration sends traffic that could
// disrupt or damage the target, and why.
//
// The engine judges; the runtime gates. Keeping the judgement here means adding
// an engine with its own notion of "intrusive" does not mean editing the scan
// runtime.
type Risk struct {
	Intrusive bool
	Reason    string
}

// Safe is the zero risk.
func Safe() Risk { return Risk{} }

// Intrusive marks a configuration as sending potentially damaging traffic.
func Intrusive(reason string) Risk { return Risk{Intrusive: true, Reason: reason} }

// String renders the risk for a confirmation prompt.
func (r Risk) String() string {
	if !r.Intrusive {
		return "safe"
	}
	if r.Reason == "" {
		return "intrusive"
	}
	return fmt.Sprintf("intrusive: %s", r.Reason)
}
