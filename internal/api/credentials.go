package api

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/flanksource/commons-db/connection"
	"github.com/flanksource/commons-db/types"

	credentialstore "github.com/flanksource/recon/internal/credentials"
)

// CredentialEnvVar is the credential wire form of types.EnvVar. Value is
// accepted on writes but never returned; Configured tells a client that an
// inline value already exists without revealing it.
type CredentialEnvVar struct {
	Name       string              `json:"name"`
	Value      string              `json:"value,omitempty"`
	ValueFrom  *types.EnvVarSource `json:"valueFrom,omitempty"`
	Configured bool                `json:"configured,omitempty"`
}

// ProviderCredentials is the provider-owned credentials nested under a target.
// Connections remains the commons-db execution contract used at runtime.
type ProviderCredentials struct {
	EnvVars     []CredentialEnvVar          `json:"envVars,omitempty"`
	Connections *connection.ExecConnections `json:"connections,omitempty"`
}

// MarshalJSON always projects the read form. It is deliberately impossible to
// serialize an inline credential through the API DTO.
func (c ProviderCredentials) MarshalJSON() ([]byte, error) {
	type envVar struct {
		Name       string              `json:"name"`
		ValueFrom  *types.EnvVarSource `json:"valueFrom,omitempty"`
		Configured bool                `json:"configured,omitempty"`
	}
	out := struct {
		EnvVars     []envVar       `json:"envVars,omitempty"`
		Connections map[string]any `json:"connections,omitempty"`
	}{}
	for _, value := range c.EnvVars {
		out.EnvVars = append(out.EnvVars, envVar{
			Name: value.Name, ValueFrom: value.ValueFrom,
			Configured: value.Configured || value.Value != "",
		})
	}
	if c.Connections != nil {
		encoded, err := json.Marshal(c.Connections)
		if err != nil {
			return nil, fmt.Errorf("encode provider credential connections: %w", err)
		}
		if err := json.Unmarshal(encoded, &out.Connections); err != nil {
			return nil, fmt.Errorf("decode provider credential connections: %w", err)
		}
		redactJSONValues(out.Connections)
	}
	return json.Marshal(out)
}

// RawMap returns the unredacted shape used only for provider JSON Schema
// validation. Callers must never log or return it.
func (c ProviderCredentials) RawMap() (map[string]any, error) {
	type raw ProviderCredentials
	encoded, err := json.Marshal(raw(c))
	if err != nil {
		return nil, fmt.Errorf("encode provider credentials: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, fmt.Errorf("decode provider credentials: %w", err)
	}
	return out, nil
}

// Empty reports whether the payload contains no credential source.
func (c ProviderCredentials) Empty() bool {
	return len(c.EnvVars) == 0 &&
		(c.Connections == nil || reflect.DeepEqual(*c.Connections, connection.ExecConnections{}))
}

// Stored converts the write DTO to the unredacted persistence/runtime type.
func (c ProviderCredentials) Stored() credentialstore.ProviderCredentials {
	out := credentialstore.ProviderCredentials{Connections: c.Connections}
	for _, value := range c.EnvVars {
		out.EnvVars = append(out.EnvVars, types.EnvVar{
			Name: value.Name, ValueStatic: value.Value, ValueFrom: value.ValueFrom,
		})
	}
	return out
}

// ProviderCredentialsFromStored converts the unredacted stored form to the API
// DTO. Its MarshalJSON method guarantees that Value is never serialized.
func ProviderCredentialsFromStored(c *credentialstore.ProviderCredentials) *ProviderCredentials {
	if c == nil {
		return nil
	}
	out := &ProviderCredentials{Connections: c.Connections}
	for _, value := range c.EnvVars {
		out.EnvVars = append(out.EnvVars, CredentialEnvVar{
			Name: value.Name, Value: value.ValueStatic, ValueFrom: value.ValueFrom,
		})
	}
	return out
}

// ValidateWrite accepts configured markers on updates while rejecting
// ambiguous EnvVars. The store resolves each marker against the locked row.
func (c ProviderCredentials) ValidateWrite() error {
	for _, value := range c.EnvVars {
		if value.Value != "" && value.ValueFrom != nil {
			return fmt.Errorf("credential %q cannot set both value and valueFrom", value.Name)
		}
		if value.Configured && (value.Value != "" || value.ValueFrom != nil) {
			return fmt.Errorf("credential %q configured marker cannot include value or valueFrom", value.Name)
		}
	}
	return nil
}

// ValidateCreate rejects configured markers because no stored value exists to
// preserve for a new target.
func (c ProviderCredentials) ValidateCreate() error {
	if err := c.ValidateWrite(); err != nil {
		return err
	}
	for _, value := range c.EnvVars {
		if value.Configured {
			return fmt.Errorf("credential %q configured marker is not allowed when creating a target", value.Name)
		}
	}
	return nil
}

func redactJSONValues(value any) {
	switch value := value.(type) {
	case map[string]any:
		if inline, ok := value["value"].(string); ok && inline != "" {
			delete(value, "value")
			value["configured"] = true
		}
		for _, child := range value {
			redactJSONValues(child)
		}
	case []any:
		for _, child := range value {
			redactJSONValues(child)
		}
	}
}
