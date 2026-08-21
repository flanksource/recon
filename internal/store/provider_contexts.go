package store

import (
	"context"
	"fmt"

	"github.com/flanksource/recon/internal/api"
	credentialstore "github.com/flanksource/recon/internal/credentials"
)

// ProviderContext is one explicit provider-native execution scope. Arguments
// retain their JSON types because the generated Prowler schema and command
// builder distinguish arrays, booleans and numbers from strings.
type ProviderContext struct {
	ID             string                               `json:"id"`
	Provider       string                               `json:"provider"`
	CredentialMode api.CredentialMode                   `json:"credentialMode"`
	Arguments      map[string]any                       `json:"arguments"`
	Class          api.Class                            `json:"class"`
	Credentials    *credentialstore.ProviderCredentials `json:"-"`
}

// ProviderContexts resolves a selector for one provider. An explicit target
// from another provider is an error rather than silently disappearing, because
// that would make a requested scope look clean without ever scanning it.
func (s *Store) ProviderContexts(
	ctx context.Context,
	opts TargetOpts,
	provider string,
) ([]ProviderContext, error) {
	if provider == "" {
		return nil, fmt.Errorf("provider is required to resolve provider contexts")
	}

	explicit := len(opts.IDs) > 0
	if explicit {
		opts.Kind = nil
		opts.Provider = nil
	} else {
		opts.Kind = []string{string(api.KindProviderContext)}
		opts.Provider = []string{provider}
	}
	targets, err := s.ListTargets(ctx, opts)
	if err != nil {
		return nil, err
	}
	if explicit {
		found := make(map[string]bool, len(targets))
		for _, target := range targets {
			found[target.ID] = true
		}
		for _, id := range opts.IDs {
			if !found[id] {
				return nil, NotFound("target", id)
			}
		}
	}

	contexts := make([]ProviderContext, 0, len(targets))
	for _, target := range targets {
		if target.Kind != api.KindProviderContext {
			return nil, fmt.Errorf("target %s is a %s, not a provider-context", target.ID, target.Kind.String())
		}
		if target.Provider != provider {
			return nil, fmt.Errorf("provider context %s uses provider %s, not %s",
				target.ID, target.Provider, provider)
		}
		var credentials *credentialstore.ProviderCredentials
		if target.Credentials != nil {
			value := target.Credentials.Stored()
			credentials = &value
		}
		contexts = append(contexts, ProviderContext{
			ID: target.ID, Provider: target.Provider,
			CredentialMode: target.CredentialMode,
			Arguments:      target.Arguments, Class: target.Class,
			Credentials: credentials,
		})
	}
	return contexts, nil
}
