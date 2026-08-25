package auth

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

func Match(provider string, arguments, credentials map[string]any) (Method, error) {
	policy, ok := ForProvider(provider)
	if !ok {
		return Method{}, fmt.Errorf("prowler provider %s has no configured credential methods", provider)
	}
	envNames, connectionKey, err := credentialSources(credentials)
	if err != nil {
		return Method{}, fmt.Errorf("prowler provider %s credentials: %w", provider, err)
	}
	var matches []Method
	for _, method := range policy.Methods {
		if methodMatches(method, envNames, connectionKey) {
			matches = append(matches, method)
		}
	}
	if len(matches) != 1 {
		return Method{}, fmt.Errorf("prowler provider %s credential set does not match exactly one authentication method", provider)
	}
	method := matches[0]
	for _, key := range method.RequiredSettings {
		if !active(arguments[key]) {
			return Method{}, fmt.Errorf("prowler provider %s authentication method %s requires setting %q", provider, method.ID, key)
		}
	}
	for _, key := range policy.Selectors {
		value, configured := arguments[key]
		if !configured || !active(value) {
			continue
		}
		expected, selected := method.Arguments[key]
		if !selected || !reflect.DeepEqual(value, expected) {
			return Method{}, fmt.Errorf("prowler provider %s authentication method %s conflicts with authentication argument %q", provider, method.ID, key)
		}
	}
	return method, nil
}

func ProjectArguments(provider string, arguments map[string]any, method *Method) (map[string]any, error) {
	policy, ok := ForProvider(provider)
	if !ok {
		return clone(arguments), nil
	}
	settings := make(map[string]bool, len(policy.Settings))
	for _, setting := range policy.Settings {
		settings[setting.Key] = true
	}
	projected := make(map[string]any, len(arguments))
	for key, value := range arguments {
		if !settings[key] {
			projected[key] = value
		}
	}
	if method != nil {
		for key, value := range method.Arguments {
			if current, found := projected[key]; found && !reflect.DeepEqual(current, value) {
				return nil, fmt.Errorf("prowler provider %s authentication argument %q conflicts with method %s", provider, key, method.ID)
			}
			projected[key] = value
		}
	}
	return projected, nil
}

func EnvironmentSettings(provider string, arguments map[string]any) (map[string]string, error) {
	policy, ok := ForProvider(provider)
	if !ok {
		return map[string]string{}, nil
	}
	projected := make(map[string]string, len(policy.Settings))
	for _, setting := range policy.Settings {
		value, found := arguments[setting.Key]
		if !found {
			continue
		}
		text, ok := value.(string)
		if !ok || strings.TrimSpace(text) == "" {
			return nil, fmt.Errorf("prowler provider %s setting %q must be a non-empty string", provider, setting.Key)
		}
		projected[setting.Environment] = text
	}
	return projected, nil
}

func ConnectionReference(credentials map[string]any, method Method) (string, error) {
	if method.Connection == nil {
		return "", nil
	}
	connections, ok := credentials["connections"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("authentication method %s requires connections", method.ID)
	}
	selected, ok := connections[method.Connection.Key].(map[string]any)
	if !ok {
		return "", fmt.Errorf("authentication method %s requires connections.%s", method.ID, method.Connection.Key)
	}
	reference, ok := selected["connection"].(string)
	if !ok || strings.TrimSpace(reference) == "" {
		return "", fmt.Errorf("authentication method %s requires connections.%s.connection", method.ID, method.Connection.Key)
	}
	return reference, nil
}

func credentialSources(credentials map[string]any) ([]string, string, error) {
	var names []string
	if raw, found := credentials["envVars"]; found {
		values, ok := raw.([]any)
		if !ok {
			return nil, "", fmt.Errorf("envVars must be an array")
		}
		for _, value := range values {
			item, ok := value.(map[string]any)
			if !ok {
				return nil, "", fmt.Errorf("envVars entries must be objects")
			}
			name, ok := item["name"].(string)
			if !ok || name == "" {
				return nil, "", fmt.Errorf("envVars entries require name")
			}
			if slices.Contains(names, name) {
				return nil, "", fmt.Errorf("envVars repeats %q", name)
			}
			names = append(names, name)
		}
	}
	slices.Sort(names)

	connectionKey := ""
	if raw, found := credentials["connections"]; found {
		connections, ok := raw.(map[string]any)
		if !ok || len(connections) != 1 {
			return nil, "", fmt.Errorf("connections must select exactly one connection")
		}
		for key := range connections {
			connectionKey = key
		}
	}
	return names, connectionKey, nil
}

func methodMatches(method Method, envNames []string, connectionKey string) bool {
	if method.Connection != nil {
		return len(envNames) == 0 && connectionKey == method.Connection.Key
	}
	if connectionKey != "" || len(envNames) != len(method.EnvVars) {
		return false
	}
	wanted := make([]string, 0, len(method.EnvVars))
	for _, variable := range method.EnvVars {
		wanted = append(wanted, variable.Name)
	}
	slices.Sort(wanted)
	return slices.Equal(envNames, wanted)
}

func active(value any) bool {
	if value == nil {
		return false
	}
	if boolean, ok := value.(bool); ok {
		return boolean
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Slice || reflected.Kind() == reflect.Array {
		return reflected.Len() > 0
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text) != ""
	}
	return true
}

func clone(values map[string]any) map[string]any {
	result := make(map[string]any, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
