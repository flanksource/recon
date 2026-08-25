package entities

import (
	"context"
	"fmt"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/entity"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/mute"
	"github.com/flanksource/recon/internal/store"
)

// registerMute exposes the findings an operator has accepted.
//
// Configuration rather than scanning: a rule is something someone decides and
// then leaves in place, like a profile, not something a run produces.
func (r *Registry) registerMute() {
	clicky.NewEntity[api.MuteRule, store.MuteOpts, api.MuteRule]("mute").
		Aliases("mutes").
		ToolGroup("configuration").
		ListWithContext(bind(r, (*store.Store).ListMutes)).
		GetWithContext(bind(r, (*store.Store).GetMute)).
		CreateWithContext(bind(r, createMute)).
		UpdateWithContext(bind2(r, updateMute)).
		DeleteWithContext(deleteMute(r)).
		Filters(r.muteFilters()...).
		WithAction(entity.TypedActionWithContext("preview", mutePreviewFlags{}, r.previewMute).
			WithShort("Report what this rule would have removed from a run that has already finished")).
		Register()
}

func createMute(st *store.Store, ctx context.Context, body map[string]any) (api.MuteRule, error) {
	var err error
	body, err = requestBody(ctx, body)
	if err != nil {
		return api.MuteRule{}, err
	}
	rule, err := api.MuteRuleFrom(body)
	if err != nil {
		return api.MuteRule{}, err
	}
	return st.CreateMute(ctx, rule)
}

// updateMute edits an existing rule. The name comes from the path, not the
// body, so an edit cannot silently rename a rule and leave the runs that cited
// the old name pointing at nothing.
func updateMute(st *store.Store, ctx context.Context, name string, body map[string]any) (api.MuteRule, error) {
	body, err := requestBody(ctx, body)
	if err != nil {
		return api.MuteRule{}, err
	}
	// The entity framework carries the address as `id` and the rule spells it
	// `name`. Both are dropped: the address comes from the path, and a body
	// that could rename a rule would leave the runs citing the old name in
	// their mutes.json pointing at something that no longer exists.
	delete(body, "id")
	delete(body, "name")

	rule, err := api.MuteRuleFrom(body)
	if err != nil {
		return api.MuteRule{}, err
	}
	rule.Name = name
	return st.UpdateMute(ctx, rule)
}

// deleteMute has no result to return, so it does not fit bind.
func deleteMute(r *Registry) func(context.Context, string) error {
	return func(ctx context.Context, name string) error {
		st, err := r.store()
		if err != nil {
			return err
		}
		return st.DeleteMute(ctx, name)
	}
}

// mutePreviewFlags choose which recorded findings a rule is tried against.
type mutePreviewFlags struct {
	Scan  string `flag:"scan" help:"Try the rule against this run only; defaults to every recorded finding"`
	Limit int    `flag:"limit" help:"Most findings to read" default:"500"`
}

func (mutePreviewFlags) ClickyActionFlags() {}

// previewMute reports what a rule would take out of runs that already happened.
//
// This is the only way to find out how much a rule takes before trusting it,
// and it exists because muting drops: once a rule is in force the findings it
// matched are not recorded, so there is nothing left to inspect afterwards.
//
// It can only speak for findings earlier runs kept — a rule already in force,
// or an engine that was told not to run a check at all, left nothing here to
// match.
func (r *Registry) previewMute(ctx context.Context, name string, opts mutePreviewFlags) (api.MutePreview, error) {
	st, err := r.store()
	if err != nil {
		return api.MutePreview{}, err
	}

	stored, err := st.GetMute(ctx, name)
	if err != nil {
		return api.MutePreview{}, err
	}

	rule := mute.Rule{MuteRule: stored}
	if len(stored.Targets) > 0 {
		selector, err := store.TargetOptsFrom(stored.Targets)
		if err != nil {
			return api.MutePreview{}, fmt.Errorf("mute rule %s targets: %w", name, err)
		}
		targets, err := st.ListTargets(ctx, selector)
		if err != nil {
			return api.MutePreview{}, err
		}
		ids := make([]string, 0, len(targets))
		for _, target := range targets {
			ids = append(ids, target.GetID())
		}
		rule.Targets = ids
	}

	findings, err := st.ListFindings(ctx, store.FindingOpts{
		Scan: scanFilter(opts.Scan), Limit: opts.Limit,
	})
	if err != nil {
		return api.MutePreview{}, err
	}

	preview := api.MutePreview{
		Rule: name, Scan: opts.Scan,
		Examined: len(findings), Findings: []api.Finding{},
	}
	for _, finding := range findings {
		matched, err := rule.Matches(finding)
		if err != nil {
			// Once, not once per finding, and reported rather than folded into
			// "matched none" — a rule that cannot be evaluated mutes nothing,
			// and its author needs to know that is why.
			if len(preview.Errors) == 0 {
				preview.Errors = append(preview.Errors, err.Error())
			}
			continue
		}
		if matched {
			preview.Matched++
			preview.Findings = append(preview.Findings, finding)
		}
	}
	return preview, nil
}

func scanFilter(scan string) []string {
	if scan == "" {
		return nil
	}
	return []string{scan}
}
