package engines

// LayerOverrides applies a run-only patch to a stored profile.
//
// A null removes the key rather than setting it. A key-union merge can only
// ever add, which makes a whole class of run-only edit unexpressible: picking
// one member of a mutually exclusive group means unsetting its siblings, and
// without a way to say so the profile's member comes back during the merge and
// the run fails validation for a combination nobody asked for.
//
// Null is free to carry that meaning because it means nothing else: an engine
// catalogue rejects a null argument outright, so no profile can be storing one.
func LayerOverrides(config, overrides map[string]any) map[string]any {
	if len(overrides) == 0 {
		return config
	}
	merged := make(map[string]any, len(config)+len(overrides))
	for key, value := range config {
		merged[key] = value
	}
	for key, value := range overrides {
		if value == nil {
			delete(merged, key)
			continue
		}
		merged[key] = value
	}
	return merged
}
