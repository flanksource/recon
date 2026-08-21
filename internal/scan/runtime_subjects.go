package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/store"
)

type resolvedSubjects struct {
	Endpoints        []store.Endpoint
	ProviderContexts []store.ProviderContext
}

type providerContextArtifact struct {
	ID             string             `json:"id"`
	Provider       string             `json:"provider"`
	CredentialMode api.CredentialMode `json:"credentialMode"`
	Arguments      map[string]any     `json:"arguments"`
	Class          api.Class          `json:"class"`
}

// subjects resolves the selector to whatever this engine scans.
//
// An engine that audits cloud accounts and one that probes services want
// different things from the same selector, and neither can use the other's: a
// project id is not an address, and an endpoint is not an account. The empty
// case is an error for both — a run against nothing reports no findings, which
// reads exactly like a clean scan.
func (r *Runtime) subjects(
	ctx context.Context,
	spec engines.Spec,
	config map[string]any,
	selector store.TargetOpts,
) (resolvedSubjects, error) {
	if spec.Subject == engines.SubjectProviderContexts {
		provider, _ := config["provider"].(string)
		contexts, err := r.Store.ProviderContexts(ctx, selector, provider)
		if err != nil {
			return resolvedSubjects{}, err
		}
		if len(contexts) == 0 {
			return resolvedSubjects{}, fmt.Errorf(
				"no %s provider contexts match %s: nothing to scan", provider, selector.Describe())
		}
		for _, subject := range contexts {
			if err := spec.ValidateContext(config, subject.Arguments); err != nil {
				return resolvedSubjects{}, fmt.Errorf("provider context %s: %w", subject.ID, err)
			}
		}
		return resolvedSubjects{ProviderContexts: contexts}, nil
	}
	if spec.Subject == engines.SubjectAccounts {
		accounts, err := r.Store.Accounts(ctx, selector)
		if err != nil {
			return resolvedSubjects{}, err
		}
		if len(accounts) == 0 {
			return resolvedSubjects{}, fmt.Errorf(
				"no cloud accounts match %s: nothing to scan", selector.Describe())
		}
		return resolvedSubjects{Endpoints: accounts}, nil
	}

	endpoints, err := r.Store.Endpoints(ctx, selector)
	if err != nil {
		return resolvedSubjects{}, err
	}
	if len(endpoints) == 0 {
		return resolvedSubjects{}, fmt.Errorf(
			"no endpoints match %s: nothing to scan", selector.Describe())
	}
	return resolvedSubjects{Endpoints: endpoints}, nil
}

func (s resolvedSubjects) count() int { return len(s.Endpoints) + len(s.ProviderContexts) }

func (s resolvedSubjects) riskTargets() []store.Endpoint {
	if len(s.ProviderContexts) == 0 {
		return s.Endpoints
	}
	targets := make([]store.Endpoint, 0, len(s.ProviderContexts))
	for _, subject := range s.ProviderContexts {
		targets = append(targets, store.Endpoint{Host: subject.ID, Class: subject.Class})
	}
	return targets
}

func (s resolvedSubjects) targetIDs() []string {
	if len(s.ProviderContexts) == 0 {
		return targetIDsOf(s.Endpoints)
	}
	targets := make([]string, 0, len(s.ProviderContexts))
	for _, subject := range s.ProviderContexts {
		targets = append(targets, subject.ID)
	}
	return targets
}

func engineProviderContexts(contexts []store.ProviderContext) []engines.ProviderContext {
	result := make([]engines.ProviderContext, 0, len(contexts))
	for _, subject := range contexts {
		result = append(result, engines.ProviderContext{
			ID: subject.ID, Provider: subject.Provider, CredentialMode: subject.CredentialMode,
			Arguments: subject.Arguments, Class: subject.Class, Credentials: subject.Credentials,
		})
	}
	return result
}

func writeSubjects(dir string, subjects resolvedSubjects) (string, error) {
	if len(subjects.ProviderContexts) == 0 {
		targets := make([]string, 0, len(subjects.Endpoints))
		for _, endpoint := range subjects.Endpoints {
			targets = append(targets, endpoint.URL)
		}
		return engines.WriteList(dir, TargetsFile, targets)
	}
	if len(subjects.Endpoints) > 0 {
		return "", fmt.Errorf("scan subjects cannot mix endpoints and provider contexts")
	}

	path := filepath.Join(dir, TargetsFile)
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create provider context list: %w", err)
	}
	encoder := json.NewEncoder(file)
	for _, subject := range subjects.ProviderContexts {
		artifact := providerContextArtifact{
			ID: subject.ID, Provider: subject.Provider, CredentialMode: subject.CredentialMode,
			Arguments: subject.Arguments, Class: subject.Class,
		}
		if err := encoder.Encode(artifact); err != nil {
			_ = file.Close()
			return "", fmt.Errorf("write provider context %s: %w", subject.ID, err)
		}
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close provider context list: %w", err)
	}
	return path, nil
}
