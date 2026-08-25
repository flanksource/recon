package main

import (
	"fmt"
	"slices"

	"github.com/flanksource/recon/internal/engines/scan/prowler/auth"
	"github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

func projectCredentialSchema(provider, title string) (schema.JSONSchema, error) {
	policy, ok := auth.ForProvider(provider)
	if !ok {
		return schema.ObjectSchema(title+" credentials", map[string]schema.JSONSchema{}), nil
	}
	credential := schema.ObjectSchema(title+" credentials", map[string]schema.JSONSchema{})
	credential.CredentialMethods = policy.Methods

	var envVars []auth.EnvVar
	var connections []auth.Connection
	for _, method := range policy.Methods {
		if len(method.EnvVars) > 0 {
			envVars = appendUniqueEnvVars(envVars, method.EnvVars...)
			methodSchema := credentialEnvVars(method.EnvVars)
			credential.OneOf = append(credential.OneOf, schema.JSONSchema{
				Properties: map[string]schema.JSONSchema{"envVars": methodSchema}, Required: []string{"envVars"},
			})
		}
		if method.Connection != nil {
			connections = append(connections, *method.Connection)
			methodSchema := credentialConnections([]auth.Connection{*method.Connection})
			credential.OneOf = append(credential.OneOf, schema.JSONSchema{
				Properties: map[string]schema.JSONSchema{"connections": methodSchema}, Required: []string{"connections"},
			})
		}
	}
	if len(credential.OneOf) != len(policy.Methods) {
		return schema.JSONSchema{}, fmt.Errorf("prowler provider %s has a credential method without envVars or a connection", provider)
	}
	if len(envVars) > 0 {
		credential.Properties["envVars"] = credentialEnvVarUnion(envVars, policy.Methods)
		credential.Order = append(credential.Order, "envVars")
	}
	if len(connections) > 0 {
		credential.Properties["connections"] = credentialConnections(connections)
		credential.Order = append(credential.Order, "connections")
	}
	credential.Sections = []schema.Section{{ID: "credentials", Title: "Credentials"}}
	return credential, nil
}

func credentialEnvVarUnion(variables []auth.EnvVar, methods []auth.Method) schema.JSONSchema {
	result := credentialEnvVars(variables)
	result.AllOf = nil
	result.MinItems = integerPointer(1)
	maximum := 1
	for _, method := range methods {
		maximum = max(maximum, len(method.EnvVars))
	}
	result.MaxItems = integerPointer(maximum)
	return result
}

func credentialEnvVars(variables []auth.EnvVar) schema.JSONSchema {
	names := make([]string, 0, len(variables))
	for _, variable := range variables {
		names = append(names, variable.Name)
	}
	item := schema.ObjectSchema("Environment credential", map[string]schema.JSONSchema{
		"name": {
			Type: "string", Title: "Name", Enum: stringsToAny(names), ReadOnly: true,
		},
		"value": {
			Type: "string", Title: "Value", Format: "password", WriteOnly: true, Sensitive: true,
		},
		"valueFrom": {
			Type: "object", Title: "Value source", Properties: credentialValueSources(),
			AdditionalProperties: boolPointer(false), MinProperties: integerPointer(1), MaxProperties: integerPointer(1),
			SecretReference: true,
		},
		"configured": {
			Type: "boolean", Title: "Configured", Const: true, ReadOnly: true,
		},
	})
	item.Required = []string{"name"}
	item.OneOf = []schema.JSONSchema{
		{Required: []string{"value"}},
		{Required: []string{"valueFrom"}},
		{Required: []string{"configured"}},
	}
	result := schema.JSONSchema{
		Type: "array", Title: "Environment variables", Description: "Credential values or references resolved at scan runtime.",
		Items: &item, MinItems: integerPointer(len(names)), MaxItems: integerPointer(len(names)), UniqueItems: true, Section: "credentials",
	}
	for _, name := range names {
		result.AllOf = append(result.AllOf, schema.JSONSchema{
			Contains: &schema.JSONSchema{Properties: map[string]schema.JSONSchema{
				"name": {Const: name},
			}},
			MinContains: integerPointer(1), MaxContains: integerPointer(1),
		})
	}
	return result
}

func credentialConnections(connections []auth.Connection) schema.JSONSchema {
	properties := make(map[string]schema.JSONSchema, len(connections))
	for _, candidate := range connections {
		connection := schema.ObjectSchema(candidate.Type+" connection", map[string]schema.JSONSchema{
			"connection": {
				Type: "string", Title: "Connection", Pattern: `^connection://[^/]+(?:/[^/]+)?$`,
				ClickyLookup: map[string]any{
					"url": "/api/v1/connection", "filter": "connection", "types": []string{candidate.Type},
				},
			},
		})
		connection.Required = []string{"connection"}
		properties[candidate.Key] = connection
	}
	result := schema.ObjectSchema("Stored connection", properties)
	for _, candidate := range connections {
		result.Required = append(result.Required, candidate.Key)
	}
	result.MinProperties = integerPointer(1)
	result.MaxProperties = integerPointer(1)
	result.Section = "credentials"
	return result
}

func appendUniqueEnvVars(existing []auth.EnvVar, candidates ...auth.EnvVar) []auth.EnvVar {
	for _, candidate := range candidates {
		if !slices.ContainsFunc(existing, func(current auth.EnvVar) bool { return current.Name == candidate.Name }) {
			existing = append(existing, candidate)
		}
	}
	return existing
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func credentialValueSources() map[string]schema.JSONSchema {
	return map[string]schema.JSONSchema{
		"secretKeyRef":    credentialKeySelector("Secret key reference"),
		"configMapKeyRef": credentialKeySelector("ConfigMap key reference"),
		"helmRef":         credentialKeySelector("Helm value reference"),
		"onePassword": {
			Type: "string", Title: "1Password reference", Description: "Reference in op://vault/item/field form.",
			Pattern: `^op://[^/]+/[^/]+/.+`,
		},
	}
}

func credentialKeySelector(title string) schema.JSONSchema {
	selector := schema.ObjectSchema(title, map[string]schema.JSONSchema{
		"name": {Type: "string", Title: "Name"},
		"key":  {Type: "string", Title: "Key"},
	})
	selector.Required = []string{"name", "key"}
	return selector
}

func boolPointer(value bool) *bool { return &value }
