package server

import "fmt"

func mergeSecretCatalogOpenAPI(document map[string]any) error {
	paths, ok := document["paths"].(map[string]any)
	if !ok {
		paths = map[string]any{}
		document["paths"] = paths
	}
	operations := map[string]map[string]any{
		"/api/v1/secrets": catalogOperation(
			"List Kubernetes secret metadata", "SecretCatalogResource",
			catalogParameter("kind", false, []string{"secret", "configmap", "helm"})),
		"/api/v1/secrets/preview": catalogOperation(
			"Preview Kubernetes secret keys", "SecretCatalogPreview",
			catalogParameter("kind", false, []string{"secret", "configmap", "helm"}),
			catalogParameter("name", true, nil)),
		"/api/v1/secrets/onepassword/vaults": catalogOperation(
			"List 1Password vault metadata", "OnePasswordVault"),
		"/api/v1/secrets/onepassword/items": catalogOperation(
			"List 1Password item metadata", "OnePasswordItem",
			catalogParameter("vault", true, nil)),
		"/api/v1/secrets/onepassword/fields": catalogOperation(
			"List 1Password field metadata", "OnePasswordField",
			catalogParameter("vault", true, nil), catalogParameter("item", true, nil)),
	}
	for path, operation := range operations {
		if _, exists := paths[path]; exists {
			return fmt.Errorf("merge secret catalog OpenAPI: path %q already exists", path)
		}
		paths[path] = map[string]any{"get": operation}
	}

	components, ok := document["components"].(map[string]any)
	if !ok {
		components = map[string]any{}
		document["components"] = components
	}
	schemas, ok := components["schemas"].(map[string]any)
	if !ok {
		schemas = map[string]any{}
		components["schemas"] = schemas
	}
	generated := map[string]any{
		"SecretCatalogResource": objectSchema(
			[]string{"name", "keys"},
			map[string]any{
				"name": map[string]any{"type": "string"},
				"keys": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			}),
		"SecretCatalogPreview": objectSchema(
			[]string{"key", "value"},
			map[string]any{
				"key": map[string]any{"type": "string"},
				"value": map[string]any{
					"type": "string", "description": "Constant mask; source values are never returned",
				},
			}),
		"OnePasswordVault": objectSchema(
			[]string{"id", "name"}, stringProperties("id", "name")),
		"OnePasswordItem": objectSchema(
			[]string{"id", "name"}, stringProperties("id", "name")),
		"OnePasswordField": objectSchema(
			[]string{"id", "label", "reference"}, stringProperties("id", "label", "reference", "section")),
	}
	for name, schema := range generated {
		if _, exists := schemas[name]; exists {
			return fmt.Errorf("merge secret catalog OpenAPI: schema %q already exists", name)
		}
		schemas[name] = schema
	}
	return nil
}

func catalogOperation(summary, schema string, parameters ...map[string]any) map[string]any {
	return map[string]any{
		"operationId": "secret_catalog_" + schema,
		"summary":     summary,
		"parameters":  parameters,
		"responses": map[string]any{
			"200": map[string]any{
				"description": "Metadata only",
				"content": map[string]any{
					"application/json": map[string]any{
						"schema": map[string]any{
							"type": "array", "items": map[string]any{"$ref": "#/components/schemas/" + schema},
						},
					},
				},
			},
		},
	}
}

func catalogParameter(name string, required bool, values []string) map[string]any {
	schema := map[string]any{"type": "string"}
	if len(values) > 0 {
		schema["enum"] = values
	}
	return map[string]any{"name": name, "in": "query", "required": required, "schema": schema}
}

func objectSchema(required []string, properties map[string]any) map[string]any {
	return map[string]any{
		"type": "object", "additionalProperties": false,
		"required": required, "properties": properties,
	}
}

func stringProperties(names ...string) map[string]any {
	properties := make(map[string]any, len(names))
	for _, name := range names {
		properties[name] = map[string]any{"type": "string"}
	}
	return properties
}
