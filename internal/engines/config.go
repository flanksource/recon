package engines

import "fmt"

// AppendValues folds extra values into a list-valued configuration key.
//
// Appending rather than assigning, because the key is usually one a profile
// already set: a profile excluding `dos` and a rule excluding `db-vendor` mean
// both, and replacing the key would quietly turn the profile's own exclusion
// back on. Existing values are kept in place and duplicates are dropped, so the
// result is stable enough to record in a run's config.json and diff.
//
// The key is left untouched when there is nothing to add, so a configuration
// that never mentioned an option does not acquire an empty one.
func AppendValues(config map[string]any, key string, values []string) error {
	if len(values) == 0 {
		return nil
	}

	existing, err := ConfigValues(config, key)
	if err != nil {
		return err
	}

	seen := make(map[string]bool, len(existing))
	for _, value := range existing {
		seen[value] = true
	}

	// []any rather than []string: the configuration is validated against the
	// engine's JSON Schema and is written to the run's config.json, and both
	// expect the shape a decoded JSON document has. A native Go slice fails
	// schema validation with an unhelpful "invalid json value".
	merged := make([]any, 0, len(existing)+len(values))
	for _, value := range existing {
		merged = append(merged, value)
	}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			merged = append(merged, value)
		}
	}

	config[key] = merged
	return nil
}

// ConfigValues reads a list-valued configuration key.
//
// A configuration reaches an engine having been through JSON, so a list is a
// []any of strings as often as it is a []string, and a single value may have
// arrived bare. All three mean the same thing here.
func ConfigValues(config map[string]any, key string) ([]string, error) {
	value, present := config[key]
	if !present || value == nil {
		return nil, nil
	}

	switch typed := value.(type) {
	case []string:
		return typed, nil
	case string:
		if typed == "" {
			return nil, nil
		}
		return []string{typed}, nil
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("option %q: expected a list of strings, got a %T element", key, item)
			}
			values = append(values, text)
		}
		return values, nil
	default:
		return nil, fmt.Errorf("option %q: expected a list of strings, got %T", key, value)
	}
}
