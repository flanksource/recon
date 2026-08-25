package store

import (
	"context"
	"fmt"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/mute"
)

// Making a rule mean something to findings that already exist.
//
// Muting used to be an ingest-time filter and nothing else: mute.Apply dropped
// matching findings as a run was written, and applyMutes recorded that it had.
// A rule created in the UI therefore did nothing at all until the next run of
// that engine — a week, for a weekly compliance profile — and an operator who
// had just accepted a finding watched it stay open. Deleting a rule was the
// mirror image: everything it suppressed stayed muted until something happened
// to re-report it.
//
// Applied only to states that are open and carry their own evidence. That is the
// set a person is actually accepting — you accept something that is currently
// failing — and it is the only set the matcher can judge honestly, because a
// rule selects on the finding's host, tags and raw document, none of which a
// state whose evidence has been resolved away still has.

// muteStatesSQL accepts what an operator decided to accept.
//
// last_seen and last_scan_id deliberately do not move. A mute is a person's
// decision rather than a run's observation, and stamping the latest scan onto it
// would make the ledger claim that run said something it never did.
const muteStatesSQL = `
UPDATE finding_states SET
    status     = 'muted',
    reason     = CAST(@reason AS text),
    muted_by   = CAST(@rule AS text),
    finding_id = NULL,
    updated_at = now()
FROM unnest(CAST(@resources AS uuid[]), CAST(@checks AS text[])) AS accepted(resource_id, check_id)
WHERE finding_states.resource_id = accepted.resource_id
  AND finding_states.check_id = accepted.check_id
  AND finding_states.engine = CAST(@engine AS text)
  AND finding_states.status IN ('open', 'manual')`

// reopenMutedBySQL releases what a rule was suppressing.
//
// Back to open rather than to some third thing: a state can only have been muted
// from open, so open is where it came from. The evidence is not re-attached —
// the next run does that, and until then the check catalogue is what renders it
// — and last_seen deliberately does not move either, so it reads as a finding
// nobody has re-checked, which is what it is.
const reopenMutedBySQL = `
UPDATE finding_states SET
    status     = 'open',
    reason     = NULL,
    muted_by   = NULL,
    updated_at = now()
WHERE muted_by = CAST(@rule AS text)
  AND status = 'muted'`

// applyMuteChange is the whole of what creating, editing, disabling or deleting
// a rule does to the ledger: release what it used to hold, then take what it now
// covers. Both halves, in that order, because an edit that narrows a rule has to
// let go of what it no longer selects. A nil rule is a deletion.
func (s *Store) applyMuteChange(ctx context.Context, name string, rule *api.MuteRule) error {
	if err := s.DB(ctx).Exec(reopenMutedBySQL, map[string]any{"rule": name}).Error; err != nil {
		return fmt.Errorf("reopen findings muted by %s: %w", name, err)
	}
	if rule == nil || !rule.Active() {
		return nil
	}
	return s.muteStates(ctx, *rule)
}

func (s *Store) muteStates(ctx context.Context, rule api.MuteRule) error {
	matcher, err := s.resolveMuteRule(ctx, rule)
	if err != nil {
		return err
	}
	states, err := s.ListFindingStatesPaged(ctx, FindingStateOpts{Status: []string{api.StatusOpen}})
	if err != nil {
		return fmt.Errorf("read open findings for mute rule %s: %w", rule.Name, err)
	}

	byEngine := map[string]resourceChecks{}
	for _, state := range states.Data {
		// Synthetic means the state has no evidence of its own and what is being
		// rendered is the check's description. Matching a rule that selects on a
		// host or a raw document against that would be guessing.
		if !rule.AppliesTo(state.Engine) || state.Finding == nil || state.Finding.Synthetic {
			continue
		}
		matched, err := matcher.Matches(*state.Finding)
		if err != nil {
			return fmt.Errorf("mute rule %s: %w", rule.Name, err)
		}
		if !matched {
			continue
		}
		pairs := byEngine[state.Engine]
		pairs.add(state.ResourceID, state.CheckID)
		byEngine[state.Engine] = pairs
	}

	for engine, pairs := range byEngine {
		if err := s.DB(ctx).Exec(muteStatesSQL, map[string]any{
			"engine": engine, "rule": rule.Name, "reason": "mute:" + rule.Name,
			"resources": stringArray(pairs.Resources), "checks": stringArray(pairs.Checks),
		}).Error; err != nil {
			return fmt.Errorf("apply mute rule %s to %s findings: %w", rule.Name, engine, err)
		}
	}
	return nil
}

// resolveMuteRule turns the stored selector into the matcher, with any target
// selector already resolved to ids. Mirrors MuteRules, which does the same once
// per run.
func (s *Store) resolveMuteRule(ctx context.Context, rule api.MuteRule) (mute.Rule, error) {
	resolved := mute.Rule{MuteRule: rule}
	if len(rule.Targets) == 0 {
		return resolved, nil
	}
	opts, err := TargetOptsFrom(rule.Targets)
	if err != nil {
		return mute.Rule{}, fmt.Errorf("mute rule %s targets: %w", rule.Name, err)
	}
	targets, err := s.ListTargets(ctx, opts)
	if err != nil {
		return mute.Rule{}, fmt.Errorf("resolve mute rule %s targets: %w", rule.Name, err)
	}
	// Non-nil even when empty: a selector that matched nothing scopes the rule to
	// nothing, which is not the same as a rule that named no selector.
	ids := make([]string, 0, len(targets))
	for _, target := range targets {
		ids = append(ids, target.GetID())
	}
	resolved.Targets = ids
	return resolved, nil
}
