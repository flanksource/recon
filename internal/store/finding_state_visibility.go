package store

// One definition of what the ledger shows.
//
// There were two. The finding-state listings joined `scans ON phase = 'done'`
// while the open-finding counts a resource row carries did not, so a badge
// reading "7 open" sat above a list of three — the same rows, filtered by two
// different answers to the same question.
//
// The join is deleted rather than copied across. A state's status already says
// whether it is failing, and deriving that from the phase of whichever run last
// touched it made a failed run *hide* findings an earlier successful run had
// opened: reconciliation stamps last_scan_id in every terminal phase and only
// the absence sweep is gated on Terminal. A run that dies partway should add
// nothing, not subtract. It also made the ledger depend on a scan row that
// carries no foreign key, so pruning a run would silently empty the listing
// rather than leave it honest about what it no longer knows.
const (
	// stateIsFinding excludes checks that have only ever passed. Those rows are
	// the compliance posture rather than a finding, and occurrences = 0 is what
	// says so: a row some verdict created, never a failure.
	stateIsFinding = `(finding_states.status <> 'resolved' OR finding_states.occurrences > 0)`

	// stateIsOpen is failing now. `manual` travels with `open` everywhere,
	// because a verdict a human still owes is not a resolved one. Every row that
	// satisfies this also satisfies stateIsFinding — only openFromFindingsSQL
	// writes these statuses, and it inserts with occurrences = 1 — which is what
	// keeps the counts and the listing in agreement.
	stateIsOpen = `finding_states.status IN ('open', 'manual')`
)

// resourceHasState builds the correlated EXISTS the resource selectors filter
// on. An empty predicate asks the weakest question — has anything ever judged
// this resource — and deliberately admits pass-only rows, because that is the
// whole difference between a clean resource and an unchecked one.
func resourceHasState(predicate string) string {
	clause := `EXISTS (SELECT 1 FROM finding_states WHERE finding_states.resource_id = resources.id`
	if predicate != "" {
		clause += " AND " + predicate
	}
	return clause + ")"
}
