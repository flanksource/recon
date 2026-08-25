package store

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"gorm.io/gorm"

	"github.com/flanksource/recon/internal/api"
)

// Reconciling a run into the ledger of what is currently true.
//
// The statements are at package scope so a test can render them without a
// database — see finding_states_sql_test.go, which is the only guard against the
// named parameters silently becoming literal text.
//
// CAST(@x AS type) throughout, never @x::type: gorm ends a named parameter at a
// space, comma, bracket or quote and not at a colon, so `@at::text` is read as a
// parameter called "at::text", matches nothing, and is emitted verbatim.

// openFromFindingsSQL opens or refreshes a state for every finding the run wrote.
//
// DISTINCT ON is not optional. Two findings for one (resource, check) in a
// single run — which nuclei produces routinely, firing several matchers at one
// URL — would otherwise make Postgres raise "ON CONFLICT DO UPDATE command
// cannot affect row a second time" and abort the whole finalize transaction,
// losing the run's terminal status along with its evidence. The lowest line
// number wins, and occurrences counts runs rather than findings.
const openFromFindingsSQL = `
INSERT INTO finding_states (
    resource_id, engine, check_id, status, severity, reason,
    first_seen, last_seen, last_open_at, first_scan_id, last_scan_id, open_scan_id,
    finding_id, occurrences, target_id, created_at, updated_at
)
SELECT f.resource_id, CAST(@engine AS text), f.template_id,
       CASE WHEN f.verdict = 'manual' THEN 'manual' ELSE 'open' END,
       f.severity, NULL,
       CAST(@at AS timestamptz), CAST(@at AS timestamptz), CAST(@at AS timestamptz),
       CAST(@scan AS uuid), CAST(@scan AS uuid), CAST(@scan AS uuid),
       f.id, 1, f.target_id, now(), now()
FROM (
    SELECT DISTINCT ON (resource_id, template_id) *
    FROM findings
    WHERE scan_id = CAST(@scan AS uuid) AND resource_id IS NOT NULL
    ORDER BY resource_id, template_id, line_no
) f
ON CONFLICT (resource_id, engine, check_id) DO UPDATE SET
    status       = EXCLUDED.status,
    severity     = EXCLUDED.severity,
    reason       = NULL,
    last_seen    = EXCLUDED.last_seen,
    last_open_at = EXCLUDED.last_open_at,
    last_scan_id = EXCLUDED.last_scan_id,
    -- Unchanged while it stays open, so "failing since" survives a re-run.
    open_scan_id = CASE WHEN finding_states.status IN ('open', 'manual')
                        THEN finding_states.open_scan_id ELSE EXCLUDED.open_scan_id END,
    finding_id   = EXCLUDED.finding_id,
    resolved_at  = NULL,
    -- A run reporting it failing is the engine disagreeing with the mute, or the
    -- rule no longer covering it. Either way it is not muted any more.
    muted_by     = NULL,
    -- Runs that reported it failing, and not the same run twice: finalize is
    -- retried on a transient failure, and an unguarded increment would inflate
    -- "failing for N runs" every time.
    occurrences  = finding_states.occurrences
                   + CASE WHEN finding_states.last_scan_id = EXCLUDED.last_scan_id THEN 0 ELSE 1 END,
    updated_at   = now()
-- Never regress on a replayed or out-of-order run, which is the guard
-- upsertResources already carries and this statement did not. The timestamp is
-- the scan's own finished_at rather than now(), so re-importing an older
-- artifact used to rewrite the current posture to a stale one.
WHERE EXCLUDED.last_seen >= finding_states.last_seen`

// verdictSQL applies the explicit verdicts a resource carried: the passes that
// resolve a check and the suppressions that mute one.
//
// Applied in every terminal phase, cancelled included. A pass is a positive
// statement about a check that genuinely ran; cancelling a run truncates the set
// of statements it made, it does not falsify the ones already made.
//
// The last two predicates are what stop a verdict from erasing a failure.
// This runs after openFromFindingsSQL, so without them a run that says both FAIL
// and PASS for one (resource, check) opens the failure and then immediately
// resolves it with reason 'passed' and finding_id NULL — the evidence row
// survives while the ledger claims the check passed. That collision is not
// hypothetical: prowler synthesises an account-level resource for records naming
// none, so two records differing only by region collapse onto one pair. A
// failure observed once is a failure, so the run's own open state wins.
const verdictSQL = `
UPDATE finding_states SET
    status      = CAST(@status AS text),
    reason      = CAST(@reason AS text),
    muted_by    = NULLIF(CAST(@mutedBy AS text), ''),
    finding_id  = NULL,
    last_seen   = CAST(@at AS timestamptz),
    last_scan_id = CAST(@scan AS uuid),
    resolved_at = CASE WHEN finding_states.status IN ('open', 'manual')
                       THEN CAST(@at AS timestamptz) ELSE finding_states.resolved_at END,
    updated_at  = now()
FROM unnest(CAST(@resources AS uuid[]), CAST(@checks AS text[])) AS verdict(resource_id, check_id)
WHERE finding_states.resource_id = verdict.resource_id
  AND finding_states.check_id = verdict.check_id
  AND finding_states.engine = CAST(@engine AS text)
  AND NOT (finding_states.last_scan_id = CAST(@scan AS uuid)
           AND finding_states.status IN ('open', 'manual'))
  AND CAST(@at AS timestamptz) >= finding_states.last_seen`

// insertVerdictSQL records a check that has only ever passed.
//
// Without it the ledger would hold only the things that have gone wrong, and
// "this bucket has been checked for public access forty times and passed every
// time" — the compliance posture — would have nowhere to live.
const insertVerdictSQL = `
INSERT INTO finding_states (
    resource_id, engine, check_id, status, severity, reason,
    first_seen, last_seen, first_scan_id, last_scan_id, occurrences, created_at, updated_at
)
SELECT verdict.resource_id, CAST(@engine AS text), verdict.check_id,
       CAST(@status AS text), 'unknown', CAST(@reason AS text),
       CAST(@at AS timestamptz), CAST(@at AS timestamptz),
       CAST(@scan AS uuid), CAST(@scan AS uuid), 0, now(), now()
FROM unnest(CAST(@resources AS uuid[]), CAST(@checks AS text[])) AS verdict(resource_id, check_id)
ON CONFLICT (resource_id, engine, check_id) DO NOTHING`

// resolveAbsentSQL closes what a covering run did not restate.
//
// The predicate is `last_scan_id <> this run`, and that is the whole trick: the
// statements above stamped every pair the run did restate, so anything still
// carrying an older run is by definition unmentioned. Scoped to the checks this
// run actually produced a verdict for and the accounts its resources fell in, so
// a run over one account leaves the other alone and `--check apikeys_*` leaves
// compute findings alone.
const resolveAbsentSQL = `
UPDATE finding_states SET
    status       = 'resolved',
    reason       = CASE WHEN r.last_scan_id = CAST(@scan AS uuid)
                        THEN 'not-reported' ELSE 'resource-absent' END,
    resolved_at  = CAST(@at AS timestamptz),
    last_seen    = CAST(@at AS timestamptz),
    last_scan_id = CAST(@scan AS uuid),
    finding_id   = NULL,
    updated_at   = now()
FROM resources r
WHERE finding_states.resource_id = r.id
  AND finding_states.status IN ('open', 'manual')
  AND finding_states.engine = CAST(@engine AS text)
  AND finding_states.last_scan_id <> CAST(@scan AS uuid)
  AND finding_states.check_id = ANY(CAST(@checks AS text[]))
  AND CAST(@at AS timestamptz) >= finding_states.last_seen
  AND EXISTS (
      SELECT 1 FROM unnest(CAST(@providers AS text[]), CAST(@accounts AS text[]))
                 AS covered(provider, scope)
      WHERE covered.provider = r.provider AND covered.scope = r.scope)`

// markAbsentSQL records a resource a covering run no longer sees.
//
// It runs after resolveAbsentSQL, which reads resources.last_scan_id to tell a
// vanished resource from a merely unmentioned check.
//
// Scoped by the classes of thing the run actually enumerated as well as by
// account, and that is the whole difference between an inference and a guess:
// recon cannot tell "the bucket is gone" from "this run never looked at
// buckets". A run filtered to `--check apikeys_*` enumerates keys and nothing
// else, so without the guard it would mark the entire estate absent on the
// strength of never having asked. Seeing one bucket is what proves the run
// enumerated buckets, and only then is a bucket it did not see actually missing.
//
// The class is (kind, service) rather than `type`. resources.hcl calls `type`
// "descriptive, never identity" for a reason — prowler types one project four
// different ways in a single run depending on which service the check belongs
// to — so a resource whose type drifted between runs escaped the sweep, while
// `type`'s empty default let one untyped resource license marking every untyped
// resource in scope absent. kind and service are both stable across runs, and
// an empty service is a real class rather than an accident of defaulting.
const markAbsentSQL = `
UPDATE resources SET
    state      = 'absent',
    absent_at  = CAST(@at AS timestamptz),
    updated_at = now()
WHERE state = 'present'
  AND CAST(@engine AS text) = ANY(engines)
  AND last_scan_id <> CAST(@scan AS uuid)
  AND CAST(@at AS timestamptz) >= last_seen
  AND EXISTS (
      SELECT 1 FROM unnest(CAST(@providers AS text[]), CAST(@accounts AS text[]))
                 AS covered(provider, scope)
      WHERE covered.provider = resources.provider AND covered.scope = resources.scope)
  AND EXISTS (
      SELECT 1 FROM unnest(CAST(@kinds AS text[]), CAST(@services AS text[]))
                 AS enumerated(kind, service)
      WHERE enumerated.kind = resources.kind AND enumerated.service = resources.service)`

// reconcileOptions is what the ledger needs to know about a finished run.
type reconcileOptions struct {
	ScanID string
	Engine string
	At     time.Time

	// Resources are what the run examined, already resolved to their ids.
	Resources []api.Resource
	IDs       map[api.ResourceKey]string

	// Terminal reports a run that ran to completion. A failed or cancelled run
	// still records the verdicts it made but may resolve nothing from silence:
	// it stopped early, and what it did not say is not evidence of anything.
	Terminal bool

	// PassRecorded says the engine reports a verdict per check. Prowler and
	// InSpec do; nuclei and trivy do not, and for them a template that matched
	// nothing did not pass. Without it, absence proves nothing and an open state
	// simply keeps an ageing last_seen — which is the truth.
	PassRecorded bool

	// Muted are the findings a rule removed and MutedBy is mute.Result.ByRule,
	// naming the rule that removed each line. Recorded because the findings are
	// not: a muted check would otherwise keep whatever state it had — open, with
	// an ageing last_seen — indistinguishable from one nobody rechecked.
	Muted   []api.Finding
	MutedBy map[string][]int
}

// reconcileFindingStates folds one run into the ledger.
func reconcileFindingStates(db *gorm.DB, options reconcileOptions) error {
	if options.Engine == "" || options.ScanID == "" {
		return fmt.Errorf("reconcile findings: a run needs an engine and an id")
	}

	// 0. What the checks this run described actually are. First, so a state
	// opened below always has a catalogue entry to render from — including once
	// its evidence has been resolved away or pruned.
	if err := upsertChecks(db, options.ScanID, options.Engine, options.At); err != nil {
		return err
	}

	// 1. Everything the run reported failing.
	if err := db.Exec(openFromFindingsSQL, map[string]any{
		"scan": options.ScanID, "engine": options.Engine, "at": options.At,
	}).Error; err != nil {
		return fmt.Errorf("open findings for %s: %w", options.ScanID, err)
	}

	// 2 and 3. The explicit verdicts each resource carried.
	passes, suppressed := verdicts(options)
	for _, applied := range []struct {
		pairs   resourceChecks
		verdict verdict
	}{
		{passes, verdict{Status: api.StatusResolved, Reason: api.ReasonPassed}},
		{suppressed, verdict{Status: api.StatusMuted, Reason: api.ReasonSuppressed}},
	} {
		if err := applyVerdicts(db, options, applied.pairs, applied.verdict); err != nil {
			return err
		}
	}

	// 4. What a mute rule removed before the run was written.
	if err := applyMutes(db, options); err != nil {
		return err
	}

	// 5 and 6. What a run entitled to say so no longer sees. Skipped entirely
	// for a run that did not finish, or for an engine with no verdict to report
	// — the single guard against a truncated run mass-resolving an estate.
	if !options.Terminal || !options.PassRecorded {
		return nil
	}
	scope := coverage(options)
	if len(scope.Checks) == 0 || len(scope.Accounts) == 0 {
		return nil
	}
	arguments := map[string]any{
		"scan": options.ScanID, "engine": options.Engine, "at": options.At,
		"checks":    stringArray(scope.Checks),
		"providers": stringArray(scope.Providers), "accounts": stringArray(scope.Accounts),
		"kinds": stringArray(scope.Kinds), "services": stringArray(scope.Services),
	}
	if err := db.Exec(resolveAbsentSQL, arguments).Error; err != nil {
		return fmt.Errorf("resolve absent findings for %s: %w", options.ScanID, err)
	}
	if err := db.Exec(markAbsentSQL, arguments).Error; err != nil {
		return fmt.Errorf("mark absent resources for %s: %w", options.ScanID, err)
	}
	return nil
}

// resourceChecks is a set of (resource id, check) pairs, carried as parallel
// arrays because that is what unnest takes.
type resourceChecks struct {
	Resources []string
	Checks    []string
}

func (p *resourceChecks) add(resourceID, check string) {
	p.Resources = append(p.Resources, resourceID)
	p.Checks = append(p.Checks, check)
}

func (p resourceChecks) empty() bool { return len(p.Resources) == 0 }

func verdicts(options reconcileOptions) (passes, suppressed resourceChecks) {
	for _, resource := range options.Resources {
		id, known := options.IDs[resource.Key()]
		if !known {
			continue
		}
		for _, check := range resource.Passed {
			passes.add(id, check)
		}
		for _, check := range resource.Suppressed {
			suppressed.add(id, check)
		}
	}
	return passes, suppressed
}

// verdict is one status the reconciler writes over a set of (resource, check)
// pairs. MutedBy names the rule when the status is muted and is empty otherwise,
// which is what clears the attribution when a pass supersedes a mute.
type verdict struct {
	Status, Reason, MutedBy string
}

func applyVerdicts(db *gorm.DB, options reconcileOptions, pairs resourceChecks, applied verdict) error {
	if pairs.empty() {
		return nil
	}
	arguments := map[string]any{
		"scan": options.ScanID, "engine": options.Engine, "at": options.At,
		"status": applied.Status, "reason": applied.Reason, "mutedBy": applied.MutedBy,
		"resources": stringArray(pairs.Resources), "checks": stringArray(pairs.Checks),
	}
	status := applied.Status
	// Insert first so a check that has only ever passed gets a row, then update
	// so one that was open is closed. The insert does nothing where a row
	// already exists, which is what leaves the update the only writer of status.
	if err := db.Exec(insertVerdictSQL, arguments).Error; err != nil {
		return fmt.Errorf("record %s verdicts for %s: %w", status, options.ScanID, err)
	}
	if err := db.Exec(verdictSQL, arguments).Error; err != nil {
		return fmt.Errorf("apply %s verdicts for %s: %w", status, options.ScanID, err)
	}
	return nil
}

// applyMutes records what a rule removed.
//
// mute.Apply drops these before the run is written, so without this a check
// somebody muted would keep whatever state it had — open, with an ageing
// last_seen — and read as a problem nobody is looking at rather than one
// somebody accepted.
func applyMutes(db *gorm.DB, options reconcileOptions) error {
	if len(options.Muted) == 0 {
		return nil
	}

	// First rule wins, by name, which is the order ListMutes returns and the
	// order mute.Apply attributes in. Iterating the map directly attributed a
	// line two rules both matched to whichever one Go reached last, so the same
	// run over the same input could record a different rule each time.
	rules := map[int]string{}
	for _, rule := range slices.Sorted(maps.Keys(options.MutedBy)) {
		for _, line := range options.MutedBy[rule] {
			if _, taken := rules[line]; !taken {
				rules[line] = rule
			}
		}
	}
	byRule := map[string]resourceChecks{}
	for _, finding := range options.Muted {
		// A muted finding with no resource this run emitted has no ledger row to
		// mute, which is the same lesser thing an unattached finding is — see
		// saveFindings. It is not a reason to fail the run: muting a host-shaped
		// nuclei finding is an ordinary thing to configure, and erroring here
		// cost the entire finalize transaction.
		if len(finding.Resources) == 0 {
			continue
		}
		id, err := resolveResource(options.IDs, finding.Resources[0])
		if err != nil {
			continue
		}
		rule := rules[finding.LineNo]
		pairs := byRule[rule]
		pairs.add(id, finding.TemplateID)
		byRule[rule] = pairs
	}

	// Sorted, because MutedBy is a map and a finding two rules both match would
	// otherwise be attributed to whichever one Go happened to iterate last.
	// ListMutes orders by name and attributes a finding to the first rule that
	// matches it; this is the same rule applied to the same question.
	for _, rule := range slices.Sorted(maps.Keys(byRule)) {
		reason := "mute"
		if rule != "" {
			reason = "mute:" + rule
		}
		if err := applyVerdicts(db, options, byRule[rule], verdict{
			Status: api.StatusMuted, Reason: reason, MutedBy: rule,
		}); err != nil {
			return err
		}
	}
	return nil
}

// covered is what a run is entitled to resolve: the checks it produced a verdict
// for, the accounts its resources fell in, and the classes of thing it actually
// enumerated.
//
// The accounts and the classes are parallel arrays rather than joined strings.
// `provider || '/' || scope` was one value to compare, but scope is "the
// account, project or registry" and a registry path contains slashes of its own,
// so gcr.io/team and gcr.io + /team were the same key.
type covered struct {
	Checks              []string
	Providers, Accounts []string
	Kinds, Services     []string
}

// coverage reads that off what the run actually reported rather than off the
// profile it was configured with. That is the honest source — a filtered run's
// coverage is what it filtered down to — and it is also the only one that
// survives a profile being edited between runs. Deliberately not
// Catalogue.Preview either: api.TemplatePreview.Caveats exists precisely because
// the preview "may overstate what runs", and resolving a finding on an
// overstatement is a false all-clear.
func coverage(options reconcileOptions) covered {
	checkSet := map[string]struct{}{}
	accountSet := map[[2]string]struct{}{}
	classSet := map[[2]string]struct{}{}
	for _, resource := range options.Resources {
		accountSet[[2]string{resource.Provider, resource.Scope}] = struct{}{}
		classSet[[2]string{resource.Kind, resource.Service}] = struct{}{}
		for _, check := range resource.Passed {
			checkSet[check] = struct{}{}
		}
		for _, check := range resource.Suppressed {
			checkSet[check] = struct{}{}
		}
	}
	out := covered{Checks: keys(checkSet)}
	out.Providers, out.Accounts = pairs(accountSet)
	out.Kinds, out.Services = pairs(classSet)
	return out
}

// pairs splits a set of two-part keys into the parallel arrays unnest takes.
func pairs(set map[[2]string]struct{}) (first, second []string) {
	first = make([]string, 0, len(set))
	second = make([]string, 0, len(set))
	for pair := range set {
		first = append(first, pair[0])
		second = append(second, pair[1])
	}
	return first, second
}

func resolveResource(ids map[api.ResourceKey]string, ref api.ResourceRef) (string, error) {
	key := api.ResourceKey{Provider: ref.Provider, Scope: ref.Scope, UID: ref.UID}
	if err := key.Validate(); err != nil {
		return "", fmt.Errorf("invalid resource reference: %w", err)
	}
	if id, found := ids[key]; found {
		return id, nil
	}
	return "", fmt.Errorf("%s/%s/%s was not emitted by the run", key.Provider, key.Scope, key.UID)
}

func keys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	return out
}
