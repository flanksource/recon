package main

import (
	"fmt"

	"github.com/flanksource/recon/internal/engines/scan/prowler/schema"
)

type credentialPolicy struct {
	EnvVars []string
}

var providerCredentialPolicies = map[string]credentialPolicy{
	"alibabacloud":    {},
	"aws":             {},
	"azure":           {},
	"cloudflare":      {EnvVars: []string{"CLOUDFLARE_API_TOKEN"}},
	"e2enetworks":     {},
	"gcp":             {},
	"github":          {},
	"googleworkspace": {},
	"huaweicloud":     {},
	"iac":             {},
	"image":           {},
	"kubernetes":      {},
	"linode":          {},
	"llm":             {},
	"m365":            {},
	"mongodbatlas":    {},
	"nhn":             {},
	"okta":            {},
	"openstack":       {},
	"oraclecloud":     {},
	"scaleway":        {},
	"stackit":         {},
	"vercel":          {},
}

func projectCredentialSchema(provider, title string) (schema.JSONSchema, error) {
	policy, ok := providerCredentialPolicies[provider]
	if !ok {
		return schema.JSONSchema{}, fmt.Errorf("prowler provider %s has no credential security policy", provider)
	}
	credential := schema.ObjectSchema(title+" credentials", map[string]schema.JSONSchema{})
	if len(policy.EnvVars) == 0 {
		return credential, nil
	}
	if len(policy.EnvVars) != 1 {
		return schema.JSONSchema{}, fmt.Errorf("prowler provider %s credential policy must expose exactly one environment variable", provider)
	}

	credential.Properties["envVars"] = credentialEnvVars(policy.EnvVars[0])
	credential.Order = []string{"envVars"}
	credential.Sections = []schema.Section{{ID: "credentials", Title: "Credentials"}}
	return credential, nil
}

func credentialEnvVars(name string) schema.JSONSchema {
	item := schema.ObjectSchema("Environment credential", map[string]schema.JSONSchema{
		"name": {
			Type: "string", Title: "Name", Const: name, ReadOnly: true,
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
	return schema.JSONSchema{
		Type: "array", Title: "Environment variables", Description: "Credential values or references resolved at scan runtime.",
		Items: &item, MinItems: integerPointer(1), MaxItems: integerPointer(1), Section: "credentials",
	}
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
