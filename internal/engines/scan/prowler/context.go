package prowler

import (
	"fmt"

	"github.com/flanksource/recon/internal/api"
	credentialstore "github.com/flanksource/recon/internal/credentials"
	"github.com/flanksource/recon/internal/engines"
)

type providerContext struct {
	ID             string                               `json:"id"`
	Provider       string                               `json:"provider"`
	CredentialMode api.CredentialMode                   `json:"credentialMode"`
	Arguments      map[string]any                       `json:"arguments"`
	Class          api.Class                            `json:"class"`
	Credentials    *credentialstore.ProviderCredentials `json:"-"`
}

func providerContextsForRun(subjects []engines.ProviderContext, provider string) ([]providerContext, error) {
	if len(subjects) == 0 {
		return nil, fmt.Errorf("prowler run has no in-memory provider contexts")
	}
	contexts := make([]providerContext, 0, len(subjects))
	seen := make(map[string]struct{}, len(subjects))
	for _, subject := range subjects {
		context := providerContext{
			ID: subject.ID, Provider: subject.Provider, CredentialMode: subject.CredentialMode,
			Arguments: subject.Arguments, Class: subject.Class, Credentials: subject.Credentials,
		}
		if err := validateProviderContext(context, provider); err != nil {
			return nil, err
		}
		if _, found := seen[context.ID]; found {
			return nil, fmt.Errorf("duplicate provider context %q", context.ID)
		}
		seen[context.ID] = struct{}{}
		contexts = append(contexts, context)
	}
	return contexts, nil
}

func validateProviderContext(subject providerContext, provider string) error {
	if subject.ID == "" {
		return fmt.Errorf("provider context id is required")
	}
	if subject.Provider != provider {
		return fmt.Errorf("provider context %s uses provider %s, not %s", subject.ID, subject.Provider, provider)
	}
	if !subject.CredentialMode.Valid() {
		return fmt.Errorf("provider context %s has invalid credential mode %q", subject.ID, subject.CredentialMode)
	}
	if subject.Arguments == nil {
		return fmt.Errorf("provider context %s arguments are required", subject.ID)
	}
	return nil
}

func mergeContextInputs(profile, context map[string]any) (map[string]any, error) {
	merged := make(map[string]any, len(profile)+len(context))
	for key, value := range profile {
		merged[key] = value
	}
	for key, value := range context {
		if _, found := merged[key]; found {
			return nil, fmt.Errorf("argument %q is set by both profile and provider context", key)
		}
		merged[key] = value
	}
	return merged, nil
}
