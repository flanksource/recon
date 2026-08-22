package prowler

import (
	"strings"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/mute"
)

var _ scan.Muter = Engine{}

// excludedChecks is the only option a mute rule can become.
//
// Not severities, and not by design accident: Prowler's severity option is an
// include-list, and turning "mute info" into "run everything except info" is
// only correct if the vocabulary is closed and the profile has not already set
// the key. Those are two conditions nobody will re-check, and getting either
// wrong silently drops checks the rule never covered. Prowler has no tag
// exclusion at all.
const excludedChecks = "excluded-checks"

// Pushdown folds the rules Prowler can express into its own check exclusions.
//
// Into the configuration, which selectChecks already reads, so the catalogue
// preview reports what a run will actually cover without any change to it.
func (Engine) Pushdown(request scan.PushdownRequest) (scan.Pushdown, error) {
	plan := scan.Pushdown{Plan: mute.Plan{PushedDown: map[string]string{}}}

	provider, _ := request.Config["provider"].(string)
	if provider == "" {
		return plan, nil
	}

	for _, rule := range request.Rules {
		if rule.Pushable() != mute.DimensionTemplates {
			continue
		}
		checks, expressible := checkIDs(provider, rule.Templates)
		if !expressible {
			continue
		}
		if err := engines.AppendValues(request.Config, excludedChecks, checks); err != nil {
			return scan.Pushdown{}, err
		}
		plan.Plan.PushedDown[rule.Name] = excludedChecks
	}
	return plan, nil
}

// checkIDs turns the rule's template patterns into the bare check ids Prowler
// excludes by, and reports whether every one of them could be turned.
//
// Two translations have to hold, and if either fails for any value the whole
// rule is left to be applied to the results — a partly pushed rule would
// exclude some checks outright while still matching others afterwards, and the
// checks it excluded would leave nothing behind to show for it.
//
// A finding's template id is the provider-qualified key (`gcp/bucket_public`)
// while --excluded-checks names the check alone (`bucket_public`), so a value
// has to carry this run's provider to mean anything here. And Prowler excludes
// by name, not by pattern, so a glob cannot be handed over even though the rule
// itself matches with one.
func checkIDs(provider string, patterns []string) ([]string, bool) {
	prefix := provider + "/"
	ids := make([]string, 0, len(patterns))

	for _, pattern := range patterns {
		if strings.ContainsAny(pattern, "*?[") {
			return nil, false
		}
		id, qualified := strings.CutPrefix(pattern, prefix)
		if !qualified || id == "" {
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, len(ids) > 0
}
