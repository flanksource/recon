package store

import (
	"context"
	"fmt"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/mute"
)

// MuteOpts selects mute rules.
type MuteOpts struct {
	Engine   []string `json:"engine,omitempty" flag:"engine" help:"Only rules that apply to these engines"`
	Severity []string `json:"severity,omitempty" flag:"severity" help:"Only rules naming these severities"`
	Template []string `json:"template,omitempty" flag:"template" help:"Only rules naming these template ids"`
	Disabled bool     `json:"disabled,omitempty" flag:"disabled" help:"Only rules that are switched off"`
}

// ListMutes returns the rules a selector matches, ordered by name.
//
// Name order is not cosmetic: a finding is attributed to the first rule that
// matches it, so a stable order is what keeps a run's mutes.json saying the
// same thing twice.
func (s *Store) ListMutes(ctx context.Context, opts MuteOpts) ([]api.MuteRule, error) {
	query := s.DB(ctx).Model(&models.MuteRule{})

	// A rule naming no engine applies to every engine, so it has to survive an
	// engine filter — otherwise the filter would hide the rules with the widest
	// reach, which are the ones worth seeing.
	if len(opts.Engine) > 0 {
		query = query.Where("engines = '{}' OR engines && ?", stringArray(opts.Engine))
	}
	if len(opts.Severity) > 0 {
		query = query.Where("severity && ?", stringArray(opts.Severity))
	}
	if len(opts.Template) > 0 {
		query = query.Where("templates && ?", stringArray(opts.Template))
	}
	if opts.Disabled {
		query = query.Where("disabled")
	}

	var rows []models.MuteRule
	if err := query.Order("name").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list mute rules: %w", err)
	}

	rules := make([]api.MuteRule, 0, len(rows))
	for _, row := range rows {
		rules = append(rules, row.Document())
	}
	return rules, nil
}

// GetMute returns one rule.
func (s *Store) GetMute(ctx context.Context, name string) (api.MuteRule, error) {
	var row models.MuteRule
	err := s.DB(ctx).Where("name = ?", name).First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return api.MuteRule{}, NotFound("mute", name)
		}
		return api.MuteRule{}, fmt.Errorf("get mute rule %s: %w", name, err)
	}
	return row.Document(), nil
}

func validateMuteRule(rule api.MuteRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	for _, engine := range rule.Engines {
		if _, err := scan.Get(engine); err != nil {
			return fmt.Errorf("mute rule %s: %w", rule.Name, err)
		}
	}
	if _, err := TargetOptsFrom(rule.Targets); err != nil {
		return fmt.Errorf("mute rule %s targets: %w", rule.Name, err)
	}
	if err := mute.Compile(rule.Expr); err != nil {
		return fmt.Errorf("mute rule %s: %w", rule.Name, err)
	}
	return nil
}

// CreateMute validates and inserts a new rule. Duplicate names fail rather
// than silently replacing a rule with a different scope.
func (s *Store) CreateMute(ctx context.Context, rule api.MuteRule) (api.MuteRule, error) {
	if err := validateMuteRule(rule); err != nil {
		return api.MuteRule{}, err
	}
	row := models.MuteRuleFrom(rule)
	if err := s.DB(ctx).Create(&row).Error; err != nil {
		return api.MuteRule{}, fmt.Errorf("create mute rule %s: %w", rule.Name, err)
	}
	if err := s.applyMuteChange(ctx, rule.Name, &rule); err != nil {
		return api.MuteRule{}, err
	}
	return s.GetMute(ctx, rule.Name)
}

// UpdateMute validates and replaces every editable field on an existing rule.
func (s *Store) UpdateMute(ctx context.Context, rule api.MuteRule) (api.MuteRule, error) {
	if err := validateMuteRule(rule); err != nil {
		return api.MuteRule{}, err
	}
	row := models.MuteRuleFrom(rule)
	result := s.DB(ctx).Model(&models.MuteRule{}).Where("name = ?", rule.Name).Updates(map[string]any{
		"comment": row.Comment, "disabled": row.Disabled, "engines": row.Engines,
		"targets": row.Targets, "resources": row.Resources, "resource_keys": row.ResourceKeys,
		"templates": row.Templates, "tags": row.Tags, "severity": row.Severity,
		"expr": row.Expr, "updated_at": time.Now(),
	})
	if result.Error != nil {
		return api.MuteRule{}, fmt.Errorf("update mute rule %s: %w", rule.Name, result.Error)
	}
	if result.RowsAffected == 0 {
		return api.MuteRule{}, NotFound("mute", rule.Name)
	}
	// Both halves: an edit that narrows a rule has to release what it no longer
	// covers, not merely take what it now does.
	if err := s.applyMuteChange(ctx, rule.Name, &rule); err != nil {
		return api.MuteRule{}, err
	}
	return s.GetMute(ctx, rule.Name)
}

// DeleteMute removes a rule and reopens what it was suppressing.
//
// Findings an earlier run dropped are still not restored: those rows were never
// written, and what a run removed is in that run's own mutes.json. What is
// restored is the ledger — every state carrying this rule's name goes back to
// open, because "somebody accepted this" stops being true the moment the rule
// saying so is gone. Leaving them muted made a deleted rule keep suppressing
// findings indefinitely, with nothing left in the database to explain why.
func (s *Store) DeleteMute(ctx context.Context, name string) error {
	result := s.DB(ctx).Where("name = ?", name).Delete(&models.MuteRule{})
	if result.Error != nil {
		return fmt.Errorf("delete mute rule %s: %w", name, result.Error)
	}
	if result.RowsAffected == 0 {
		return NotFound("mute", name)
	}
	return s.applyMuteChange(ctx, name, nil)
}

// MuteRules returns the rules in force for one engine, with every target
// selector already resolved.
//
// Resolved once, when the run starts, so a rule covers whatever it covered at
// the beginning rather than whatever it happens to cover when a long scan ends.
func (s *Store) MuteRules(ctx context.Context, engine string) ([]mute.Rule, error) {
	stored, err := s.ListMutes(ctx, MuteOpts{})
	if err != nil {
		return nil, err
	}

	rules := make([]mute.Rule, 0, len(stored))
	for _, rule := range stored {
		if !rule.Active() || !rule.AppliesTo(engine) {
			continue
		}

		resolved := mute.Rule{MuteRule: rule}
		if len(rule.Targets) > 0 {
			opts, err := TargetOptsFrom(rule.Targets)
			if err != nil {
				return nil, fmt.Errorf("mute rule %s targets: %w", rule.Name, err)
			}
			targets, err := s.ListTargets(ctx, opts)
			if err != nil {
				return nil, fmt.Errorf("resolve mute rule %s targets: %w", rule.Name, err)
			}
			// Non-nil even when empty: a selector that matched nothing scopes the
			// rule to nothing, which is not the same as a rule that named no
			// selector and therefore covers everything.
			ids := make([]string, 0, len(targets))
			for _, target := range targets {
				ids = append(ids, target.GetID())
			}
			resolved.Targets = ids
		}
		rules = append(rules, resolved)
	}
	return rules, nil
}
