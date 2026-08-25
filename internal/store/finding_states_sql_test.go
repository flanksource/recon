package store

import (
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// The reconciliation statements, rendered without a database.
//
// Same reasoning as scans_sql_test.go, and more of it: these five statements
// carry twenty-odd named parameters between them, and the failure mode is
// silent. gorm ends a named parameter at a space, comma, bracket or quote and
// *not* at a colon, so `@at::timestamptz` binds nothing and is emitted as the
// literal text "@at::timestamptz". Postgres rejects it at run time — inside the
// finalize transaction, which loses the run's terminal status along with its
// evidence — and on a machine that cannot start Postgres nobody sees it at all.
var _ = Describe("the statements that reconcile a run into the ledger", func() {
	// Every parameter any of the statements takes. Passing the full set to each
	// one is deliberate: gorm ignores the ones a statement does not mention, and
	// a per-statement list would have to be kept in step with the SQL by hand —
	// which is exactly the drift this file exists to catch.
	arguments := map[string]any{
		"scan":      "01JSCAN",
		"engine":    "prowler",
		"at":        time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC),
		"status":    "resolved",
		"reason":    "passed",
		"rule":      "accepted-public-logs",
		"mutedBy":   "accepted-public-logs",
		"resources": stringArray([]string{"01JRESOURCE"}),
		"checks":    stringArray([]string{"gcp/apikeys_key_exists"}),
		"engines":   stringArray([]string{"prowler"}),
		// Parallel arrays, not joined strings: scope is "the account, project or
		// registry" and a registry path has slashes of its own.
		"providers": stringArray([]string{"gcp"}),
		"accounts":  stringArray([]string{"flanksource-prod"}),
		"kinds":     stringArray([]string{"cloud-resource"}),
		"services":  stringArray([]string{"apikeys"}),
	}

	render := func(statement string) string {
		GinkgoHelper()
		// The real dialector, but never connected: BindVarTo only needs to know
		// that Postgres numbers its placeholders.
		dialector := postgres.Dialector{Config: &postgres.Config{}}
		rendered := &gorm.Statement{
			DB:      &gorm.DB{Config: &gorm.Config{Dialector: dialector}},
			Clauses: map[string]clause.Clause{},
		}
		clause.NamedExpr{SQL: statement, Vars: []any{arguments}}.Build(rendered)
		return rendered.SQL.String()
	}

	statements := map[string]string{
		"open from findings": openFromFindingsSQL,
		"apply verdicts":     verdictSQL,
		"insert verdicts":    insertVerdictSQL,
		"resolve absent":     resolveAbsentSQL,
		"mark absent":        markAbsentSQL,
		"upsert checks":      upsertChecksSQL,
		"read catalogue":     catalogueSQL,
		"mute states":        muteStatesSQL,
		"reopen muted":       reopenMutedBySQL,
	}

	for name, statement := range statements {
		It("binds every named parameter in the "+name+" statement", func() {
			Expect(render(statement)).ToNot(ContainSubstring("@"))
		})

		It("gives every parameter in the "+name+" statement a type", func() {
			// Untyped, a placeholder reaches Postgres as `unknown` and the
			// statement fails to plan wherever it is compared against a uuid,
			// unnested into a pair of arrays, or written into a timestamptz
			// column — which is all five of these.
			Expect(render(statement)).To(ContainSubstring("CAST("))
		})

		It("keeps named parameters out of the comments in the "+name+" statement", func() {
			// gorm's scanner does not know what a comment is. A `@name` written
			// in a `--` line binds a real argument and emits a placeholder that
			// Postgres then discards along with the rest of the comment, so the
			// statement arrives carrying one argument more than it has
			// parameters and pgx rejects the whole thing.
			//
			// Rendering cannot catch this — the parameter binds perfectly well,
			// and the rendered SQL contains no stray '@' — so the raw text is
			// what has to be read. These statements are heavily commented by
			// design, which is exactly what makes it easy to do.
			for _, line := range strings.Split(statement, "\n") {
				comment := strings.Index(line, "--")
				if comment < 0 {
					continue
				}
				Expect(line[comment:]).ToNot(ContainSubstring("@"),
					"a named parameter in a comment binds an argument Postgres never sees")
			}
		})
	}

	// The single most likely production crash in the design, and the one thing
	// here that a rendering test can prove: two findings for the same (resource,
	// check) in one run — nuclei fires several matchers at one URL routinely —
	// would make Postgres raise "ON CONFLICT DO UPDATE command cannot affect row
	// a second time" and abort the whole finalize transaction. DISTINCT ON is
	// what stops the second row ever reaching the conflict.
	It("deduplicates findings before opening states, so one run cannot conflict with itself", func() {
		sql := render(openFromFindingsSQL)

		Expect(sql).To(ContainSubstring("SELECT DISTINCT ON (resource_id, template_id)"))
		Expect(sql).To(ContainSubstring("ORDER BY resource_id, template_id, line_no"),
			"the lowest line wins, so the surviving evidence is the engine's first report")
	})

	// Absence is inferred from `last_scan_id <> this run` and nothing else. If
	// the predicate ever became `last_scan_id IS NULL` or dropped the engine and
	// scope guards, a run over one account would resolve findings across the
	// whole estate — a clean scan that is not clean.
	It("infers absence only from a state this run did not restate", func() {
		sql := render(resolveAbsentSQL)

		Expect(sql).To(ContainSubstring("finding_states.status IN ('open', 'manual')"))
		Expect(sql).To(ContainSubstring("finding_states.last_scan_id <> CAST("))
		Expect(sql).To(ContainSubstring("finding_states.check_id = ANY(CAST("),
			"scoped to the checks the run reported, so --check apikeys_* leaves compute alone")
		Expect(sql).To(ContainSubstring("covered.provider = r.provider AND covered.scope = r.scope"),
			"scoped to the accounts the run saw, so one account's run leaves the other alone")
		Expect(sql).ToNot(ContainSubstring("|| '/' ||"),
			"provider and scope compare as two columns; a registry scope contains slashes")
	})

	// The absence sweep reads which engines describe a resource to decide whose
	// view it may judge. A scalar column was last-writer-wins on a row whose
	// identity deliberately excludes the engine, so a resource two engines both
	// described became invisible to whichever of them ran first.
	It("judges absence within one engine's view of a shared resource", func() {
		sql := render(markAbsentSQL)

		Expect(sql).To(ContainSubstring("= ANY(engines)"))
		Expect(sql).To(ContainSubstring("enumerated.kind = resources.kind"))
		Expect(sql).To(ContainSubstring("enumerated.service = resources.service"))
		Expect(sql).ToNot(ContainSubstring("type = ANY"),
			"type is descriptive, never identity: prowler types one project four ways in a run")
	})

	// first_seen and open_scan_id are the two fields that answer "how long has
	// this been wrong". Both are meant to survive a re-run, and both are one
	// careless EXCLUDED away from being reset on every scan.
	It("keeps the age of an open finding across re-runs", func() {
		sql := render(openFromFindingsSQL)

		Expect(sql).To(ContainSubstring("open_scan_id = CASE WHEN finding_states.status IN ('open', 'manual')"))
		Expect(sql).ToNot(ContainSubstring("first_seen   = EXCLUDED"),
			"first_seen is the first verdict of any kind and never moves forward")
	})

	// occurrences is "runs that reported it failing". Finalize is retried on a
	// transient failure, and an unguarded `+ 1` counted the retry, so a finding
	// could read as failing for three runs after one.
	It("counts a run once however many times it is finalized", func() {
		Expect(render(openFromFindingsSQL)).To(ContainSubstring(
			"CASE WHEN finding_states.last_scan_id = EXCLUDED.last_scan_id THEN 0 ELSE 1 END"))
	})

	// The ledger is keyed on the current truth, so every writer has to refuse a
	// run older than the one already recorded. @at is the scan's own finished_at
	// rather than now(), so without these an imported or re-finalized older
	// artifact rewrites the posture to a stale one — the guard upsertResources
	// has carried all along and these four statements did not.
	It("refuses a run older than the state it would overwrite", func() {
		Expect(render(openFromFindingsSQL)).To(ContainSubstring(
			"WHERE EXCLUDED.last_seen >= finding_states.last_seen"))

		for _, name := range []string{"apply verdicts", "resolve absent"} {
			Expect(render(statements[name])).To(ContainSubstring(
				">= finding_states.last_seen"), name+" must not accept a stale run")
		}
		Expect(render(markAbsentSQL)).To(ContainSubstring(">= last_seen"))
	})

	// verdictSQL runs after openFromFindingsSQL. A run that reports one
	// (resource, check) as both FAIL and PASS — prowler collapses two records
	// differing only by region onto one synthesised account resource — would
	// otherwise open the failure and resolve it in the same transaction, leaving
	// the evidence row behind a ledger that says the check passed.
	It("does not let a verdict erase a failure the same run reported", func() {
		Expect(render(verdictSQL)).To(ContainSubstring(
			"AND NOT (finding_states.last_scan_id = CAST("))
		Expect(render(verdictSQL)).To(ContainSubstring(
			"AND finding_states.status IN ('open', 'manual'))"))
	})
})
