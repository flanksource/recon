package server

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/flanksource/clicky/rpc"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/flanksource/recon/internal/engines"
)

type openAPIDocument struct {
	body        []byte
	contentType string
	etag        string
}

type openAPIPublisher struct {
	json openAPIDocument
	yaml openAPIDocument
}

func newOpenAPIPublisher(
	root *cobra.Command,
	converter *rpc.Config,
	components map[string]engines.JSONSchema,
) (*openAPIPublisher, error) {
	spec, err := rpc.NewOpenAPIGenerator(nil).GenerateFromCobraWithConfig(root, converter)
	if err != nil {
		return nil, fmt.Errorf("generate base OpenAPI document: %w", err)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("encode base OpenAPI document: %w", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("decode base OpenAPI document: %w", err)
	}
	if err := mergeOpenAPIComponents(document, components); err != nil {
		return nil, err
	}
	if err := mergeSecretCatalogOpenAPI(document); err != nil {
		return nil, err
	}

	jsonBody, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode merged OpenAPI JSON: %w", err)
	}
	yamlBody, err := yaml.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode merged OpenAPI YAML: %w", err)
	}
	return &openAPIPublisher{
		json: makeOpenAPIDocument(jsonBody, "application/json"),
		yaml: makeOpenAPIDocument(yamlBody, "application/yaml"),
	}, nil
}

func mergeOpenAPIComponents(document map[string]any, generated map[string]engines.JSONSchema) error {
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
	for name, schema := range generated {
		if _, exists := schemas[name]; exists {
			return fmt.Errorf("merge OpenAPI components: schema %q already exists", name)
		}
		schemas[name] = schema
	}
	return nil
}

func makeOpenAPIDocument(body []byte, contentType string) openAPIDocument {
	digest := sha256.Sum256(body)
	return openAPIDocument{
		body:        body,
		contentType: contentType,
		etag:        fmt.Sprintf(`"%x"`, digest),
	}
}

func (p *openAPIPublisher) serveJSON(w http.ResponseWriter, r *http.Request) {
	p.serve(w, r, p.json)
}

func (p *openAPIPublisher) serveYAML(w http.ResponseWriter, r *http.Request) {
	p.serve(w, r, p.yaml)
}

func (*openAPIPublisher) serve(w http.ResponseWriter, r *http.Request, document openAPIDocument) {
	w.Header().Set("ETag", document.etag)
	if r.Header.Get("If-None-Match") == document.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", document.contentType)
	_, _ = w.Write(document.body)
}
