package nuclei

import (
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/mute"
)

var _ scan.Muter = Engine{}

// muteOptions is the exclusion option each rule dimension becomes.
//
// nuclei filters on a template's own declared metadata, and each of these reads
// the same field the finding is built from — a finding's severity comes from
// the template's Info.SeverityHolder, which is exactly what -exclude-severity
// filters on. That correspondence is what makes the exclusion mean the same
// thing as the rule. A scanner that computed a finding's severity per hit
// rather than declaring it on the check would break it.
var muteOptions = map[mute.Dimension]string{
	mute.DimensionTemplates: "exclude-id",
	mute.DimensionTags:      "exclude-tags",
	mute.DimensionSeverity:  "exclude-severity",
}

// Pushdown folds the rules nuclei can express into its own exclusion options.
//
// Into the configuration rather than into types.Options, because three things
// read that configuration: Options builds what runs, buildFilter builds the
// preview, and Command renders the equivalent command line. Editing the map
// they all read keeps them saying the same thing, which is the invariant
// Command's own comment insists on — and it means a run's config.json records
// what was excluded without anything extra being written.
func (Engine) Pushdown(request scan.PushdownRequest) (scan.Pushdown, error) {
	plan := scan.Pushdown{Plan: mute.Plan{PushedDown: map[string]string{}}}

	for _, rule := range request.Rules {
		dimension := rule.Pushable()
		option, expressible := muteOptions[dimension]
		if !expressible {
			continue
		}
		if err := engines.AppendValues(request.Config, option, rule.Values(dimension)); err != nil {
			return scan.Pushdown{}, err
		}
		plan.Plan.PushedDown[rule.Name] = option
	}
	return plan, nil
}
