package entities

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
)

// Run-only configuration arrives as JSON in a single flag rather than as a
// structured field.
//
// An action's options are bound from flags, and a flag value is a string: the
// repeatable key=value grammar the profile references use cannot carry a
// number, a boolean or a list without guessing at the type, and guessing is how
// a rate limit of 50 becomes the string "50" that the engine's catalog then
// rejects. JSON is the encoding that survives the round trip — and over HTTP it
// is what the caller wrote in the first place, because a nested object in the
// request body reaches here already encoded this way.

// scanOverrides decodes the run-only configuration for a scan engine.
func scanOverrides(encoded string) (map[string]any, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, nil
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(encoded), &config); err != nil {
		return nil, fmt.Errorf("scan override must be a JSON object of configuration keys, e.g. {\"rate-limit\":50}: %w", err)
	}
	return config, nil
}

// discoveryOverrides decodes the run-only configuration for a sweep, which is
// keyed by engine because a sweep runs several of them.
func discoveryOverrides(encoded string) (map[string]map[string]any, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, nil
	}
	var byEngine map[string]map[string]any
	if err := json.Unmarshal([]byte(encoded), &byEngine); err != nil {
		return nil, fmt.Errorf(
			"discovery override must be a JSON object keyed by engine, e.g. {\"naabu\":{\"top-ports\":\"full\"}}: %w", err)
	}
	// An override for an engine that does not exist is a typo, and silently
	// dropping it would report a sweep that ran with settings it never used.
	for engine := range byEngine {
		if _, err := enginediscovery.Get(engine); err != nil {
			return nil, fmt.Errorf("discovery override: %w (known engines: %s)",
				err, strings.Join(discoveryEngineNames(), ", "))
		}
	}
	return byEngine, nil
}

func discoveryEngineNames() []string {
	specs := enginediscovery.Specs()
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Name)
	}
	sort.Strings(names)
	return names
}
