package entities

import (
	"context"
	"fmt"

	"github.com/flanksource/recon/internal/api"
)

const (
	muteScopeCheckOnResource    = "check-on-resource"
	muteScopeCheckOnHost        = "check-on-host"
	muteScopeCheckAnywhere      = "check-anywhere"
	muteScopeAnythingOnResource = "anything-on-resource"
)

type findingMuteFlags struct {
	Name    string `flag:"name" help:"Unique lowercase name for the mute rule" required:"true"`
	Comment string `flag:"comment" help:"Why this finding is accepted"`
	Scope   string `flag:"scope" help:"Mute scope: check-on-resource, check-on-host, check-anywhere or anything-on-resource" default:"check-on-resource"`
}

func (findingMuteFlags) ClickyActionFlags() {}

type resourceMuteFlags struct {
	Name    string `flag:"name" help:"Unique lowercase name for the mute rule" required:"true"`
	Comment string `flag:"comment" help:"Why findings on this resource are accepted"`
}

func (resourceMuteFlags) ClickyActionFlags() {}

func (r *Registry) muteFinding(ctx context.Context, id string, opts findingMuteFlags) (api.MuteRule, error) {
	st, err := r.store()
	if err != nil {
		return api.MuteRule{}, err
	}
	finding, err := st.GetFinding(ctx, id)
	if err != nil {
		return api.MuteRule{}, err
	}
	scan, err := st.GetScan(ctx, finding.ScanID)
	if err != nil {
		return api.MuteRule{}, fmt.Errorf("get scan for finding %s: %w", id, err)
	}
	rule, err := findingMuteRule(finding, scan.Engine, opts)
	if err != nil {
		return api.MuteRule{}, err
	}
	return st.CreateMute(ctx, rule)
}

func (r *Registry) muteResource(ctx context.Context, id string, opts resourceMuteFlags) (api.MuteRule, error) {
	st, err := r.store()
	if err != nil {
		return api.MuteRule{}, err
	}
	resource, err := st.GetResource(ctx, id)
	if err != nil {
		return api.MuteRule{}, err
	}
	rule, err := resourceMuteRule(resource, opts)
	if err != nil {
		return api.MuteRule{}, err
	}
	return st.CreateMute(ctx, rule)
}

func findingMuteRule(finding api.Finding, engine string, opts findingMuteFlags) (api.MuteRule, error) {
	if engine == "" {
		return api.MuteRule{}, fmt.Errorf("finding %s has no scan engine", finding.ID)
	}
	rule := api.MuteRule{Name: opts.Name, Comment: opts.Comment, Engines: api.StringList{engine}}
	switch opts.Scope {
	case muteScopeCheckOnResource:
		rule.Templates = api.StringList{finding.CheckID}
		key, err := primaryResourceKey(finding)
		if err != nil {
			return api.MuteRule{}, err
		}
		rule.ResourceKeys = api.StringList{key}
	case muteScopeCheckOnHost:
		if finding.Host == "" {
			return api.MuteRule{}, fmt.Errorf("finding %s has no host", finding.ID)
		}
		rule.Templates = api.StringList{finding.CheckID}
		rule.Resources = api.StringList{finding.Host}
	case muteScopeCheckAnywhere:
		rule.Templates = api.StringList{finding.CheckID}
	case muteScopeAnythingOnResource:
		key, err := primaryResourceKey(finding)
		if err != nil {
			return api.MuteRule{}, err
		}
		rule.ResourceKeys = api.StringList{key}
	default:
		return api.MuteRule{}, fmt.Errorf("unknown finding mute scope %q", opts.Scope)
	}
	return rule, nil
}

func primaryResourceKey(finding api.Finding) (string, error) {
	if len(finding.Resources) == 0 {
		return "", fmt.Errorf("finding %s has no canonical resource", finding.ID)
	}
	ref := finding.Resources[0]
	key := api.ResourceKey{Provider: ref.Provider, Scope: ref.Scope, UID: ref.UID}
	if err := key.Validate(); err != nil {
		return "", fmt.Errorf("finding %s has no canonical resource: %w", finding.ID, err)
	}
	return key.String(), nil
}

func resourceMuteRule(resource api.Resource, opts resourceMuteFlags) (api.MuteRule, error) {
	key := resource.Key()
	if err := key.Validate(); err != nil {
		return api.MuteRule{}, fmt.Errorf("resource %s has no canonical identity: %w", resource.ID, err)
	}
	return api.MuteRule{
		Name: opts.Name, Comment: opts.Comment, ResourceKeys: api.StringList{key.String()},
	}, nil
}
