package missioncontrol

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/flanksource/incident-commander/sdk"
)

// LinkedConfig is the authoritative catalog item a recon resource is pinned to.
type LinkedConfig struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

// ConfigLookupOptions selects the catalog client and item to read. Client and
// Server are injectable for tests; production resolves both from Context.
type ConfigLookupOptions struct {
	Context string
	Client  *sdk.Client
	Server  string
	ID      string
}

// LookupConfig reads one linked item from Mission Control's catalog.
func LookupConfig(ctx context.Context, options ConfigLookupOptions) (*LinkedConfig, error) {
	if options.ID == "" {
		return nil, fmt.Errorf("config id is required")
	}
	client := options.Client
	server := options.Server
	if client == nil {
		var configured *sdk.Client
		var err error
		configured, contextConfig, err := newClient(options.Context)
		if err != nil {
			return nil, err
		}
		client = configured
		server = contextConfig.Server
	}
	if server == "" {
		return nil, fmt.Errorf("mission control server is required")
	}

	items, err := client.GetCatalogItems(ctx, []string{options.ID})
	if err != nil {
		return nil, fmt.Errorf("read catalog item %s: %w", options.ID, err)
	}
	if len(items) != 1 {
		return nil, fmt.Errorf("linked catalog item %s was not found", options.ID)
	}
	link, err := linkedConfigURL(server, options.ID)
	if err != nil {
		return nil, err
	}
	return &LinkedConfig{
		ID: options.ID, Name: derefString(items[0].Name), Type: derefString(items[0].Type), URL: link,
	}, nil
}

func linkedConfigURL(server, id string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil {
		return "", fmt.Errorf("parse Mission Control server %q: %w", server, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("mission control server %q is not an absolute URL", server)
	}
	parsed.Path = strings.TrimSuffix(strings.TrimRight(parsed.Path, "/"), "/api")
	return url.JoinPath(parsed.String(), "catalog", id)
}
