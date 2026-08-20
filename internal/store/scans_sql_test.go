package store

import (
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Rendering the statement without a database, because the way this can go wrong
// is silent: gorm ends a named parameter at a space, comma, bracket or quote and
// *not* at a colon, so `@at::text` binds nothing and is written into the SQL as
// the literal text "@at::text". Postgres then rejects the statement at run time,
// which on a machine that cannot start one is a failure nobody sees.
var _ = Describe("the statement that stamps a run onto its targets", func() {
	render := func() (string, []any) {
		GinkgoHelper()
		// The real dialector, but never connected: BindVarTo only needs to know
		// that Postgres numbers its placeholders.
		dialector := postgres.Dialector{Config: &postgres.Config{}}
		statement := &gorm.Statement{
			DB:      &gorm.DB{Config: &gorm.Config{Dialector: dialector}},
			Clauses: map[string]clause.Clause{},
		}
		clause.NamedExpr{SQL: stampScannedSQL, Vars: []any{map[string]any{
			"at":    "2026-08-11T09:00:01Z",
			"count": true,
			"hosts": stringArray([]string{"a.example.test", "b.example.test"}),
			"scan":  "01JSCAN",
		}}}.Build(statement)
		return statement.SQL.String(), statement.Vars
	}

	It("binds every named parameter and leaves none in the text", func() {
		sql, vars := render()

		Expect(sql).ToNot(ContainSubstring("@"), sql)
		Expect(vars).To(HaveLen(4), "at, count, hosts and scan")
	})

	// The casts are what make the text, boolean and array parameters usable in
	// jsonb_build_object, CASE and unnest respectively, so losing one is not a
	// formatting detail.
	It("keeps each parameter inside the cast that gives it a type", func() {
		sql, _ := render()

		for _, cast := range []string{
			"jsonb_build_object('last_scan', CAST(",
			"CASE WHEN CAST(",
			"unnest(CAST(",
		} {
			Expect(sql).To(ContainSubstring(cast))
		}
		Expect(strings.Count(sql, "CAST(")).To(Equal(3))
	})
})
