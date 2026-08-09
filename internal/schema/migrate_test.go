package schema_test

import (
	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/schema"
)

// These specs need a real Postgres: the checks, the array quantifiers and the
// expression indexes are all server-side behaviour that no unit test can stand
// in for. dbtest resolves an embedded cluster (or COMMONS_DB_URL) and clones a
// sealed template, so the bundle is applied once rather than per spec.
var _ = Describe("the declarative schema", Ordered, Label("db"), func() {
	var db *dbtest.DB

	BeforeAll(func() {
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_schema",
			Provisioner: schema.NewProvisioner(),
		})
	})

	It("creates every table", func() {
		var tables []string
		rows, err := db.SQL().Query(`
			SELECT tablename FROM pg_tables
			WHERE schemaname = 'public' AND tablename NOT LIKE 'schema_migration%'
			ORDER BY tablename`)
		Expect(err).ToNot(HaveOccurred())
		defer rows.Close()
		for rows.Next() {
			var name string
			Expect(rows.Scan(&name)).To(Succeed())
			tables = append(tables, name)
		}
		Expect(rows.Err()).ToNot(HaveOccurred())

		Expect(tables).To(ConsistOf(
			"discoveries", "discovery_hosts", "discovery_unknown_hosts",
			"engine_profiles", "findings", "scans", "targets", "zones",
		))
	})

	// Applying an unchanged bundle a second time must be a no-op. If it is not,
	// something in the HCL does not round-trip through Atlas's inspector — the
	// classic cause being a generated column or an expression the planner
	// normalises differently than it was written.
	It("is idempotent", func() {
		Expect(schema.Apply(GinkgoT().Context(), db.DSN())).To(Succeed())
		Expect(schema.Apply(GinkgoT().Context(), db.DSN())).To(Succeed())
	})

	It("provides generate_ulid from the pre-phase script", func() {
		var id string
		Expect(db.SQL().QueryRow(`SELECT generate_ulid()::text`).Scan(&id)).To(Succeed())
		Expect(id).To(HaveLen(36))
	})

	Describe("the targets constraints", func() {
		insert := func(host, class string, extra ...any) error {
			reason := any(nil)
			if len(extra) > 0 {
				reason = extra[0]
			}
			_, err := db.SQL().Exec(
				`INSERT INTO targets (host, class, profiles, tags, reason)
				 VALUES ($1, $2, ARRAY['safe']::text[], '{}'::text[], $3)`,
				host, class, reason)
			return err
		}

		AfterEach(func() {
			_, err := db.SQL().Exec(`DELETE FROM targets`)
			Expect(err).ToNot(HaveOccurred())
		})

		It("accepts a well-formed target", func() {
			Expect(insert("a.example.test", "non-prod")).To(Succeed())
		})

		It("rejects an unknown class", func() {
			Expect(insert("a.example.test", "staging")).To(MatchError(ContainSubstring("targets_class_enum")))
		})

		It("rejects an uppercase host", func() {
			Expect(insert("A.example.test", "non-prod")).To(MatchError(ContainSubstring("targets_host_format")))
		})

		It("rejects a traversal in the host", func() {
			Expect(insert("a..example.test", "non-prod")).To(MatchError(ContainSubstring("targets_host_format")))
		})

		// Both directions of the JSON Schema's allOf rule, enforced in SQL so a
		// writer that bypasses the validator still cannot create the state the
		// UI has no way to represent.
		It("requires a reason when deactivated", func() {
			Expect(insert("a.example.test", "deactivated")).
				To(MatchError(ContainSubstring("targets_reason_iff_deactivated")))
		})

		It("accepts a deactivated target with a reason", func() {
			Expect(insert("a.example.test", "deactivated", "retired")).To(Succeed())
		})

		It("rejects a reason on an active target", func() {
			Expect(insert("a.example.test", "non-prod", "why")).
				To(MatchError(ContainSubstring("targets_reason_iff_deactivated")))
		})

		It("rejects an unknown profile", func() {
			_, err := db.SQL().Exec(
				`INSERT INTO targets (host, class, profiles, tags)
				 VALUES ('a.example.test', 'non-prod', ARRAY['aggressive']::text[], '{}'::text[])`)
			Expect(err).To(MatchError(ContainSubstring("targets_profiles_known")))
		})

		It("rejects an empty profiles array", func() {
			_, err := db.SQL().Exec(
				`INSERT INTO targets (host, class, profiles, tags)
				 VALUES ('a.example.test', 'non-prod', '{}'::text[], '{}'::text[])`)
			Expect(err).To(MatchError(ContainSubstring("targets_profiles_known")))
		})

		DescribeTable("bounds curated ports",
			func(ports string, succeeds bool) {
				_, err := db.SQL().Exec(
					`INSERT INTO targets (host, class, profiles, tags, ports)
					 VALUES ('a.example.test', 'non-prod', ARRAY['safe']::text[], '{}'::text[], ` + ports + `)`)
				if succeeds {
					Expect(err).ToNot(HaveOccurred())
					return
				}
				Expect(err).To(MatchError(ContainSubstring("targets_ports_bounded")))
			},
			Entry("a valid list", "ARRAY[443,6443]::integer[]", true),
			Entry("NULL for absent", "NULL", true),
			Entry("zero", "ARRAY[0]::integer[]", false),
			Entry("above the maximum", "ARRAY[65536]::integer[]", false),
			Entry("an empty array", "'{}'::integer[]", false),
		)
	})

	Describe("findings", func() {
		It("cascades when its scan is deleted", func() {
			var scanID string
			Expect(db.SQL().QueryRow(`
				INSERT INTO scans (name, engine, profile, phase, started_at)
				VALUES ('safe-x-20260101-000000.jsonl', 'nuclei', 'safe', 'done', now())
				RETURNING id::text`).Scan(&scanID)).To(Succeed())

			_, err := db.SQL().Exec(`
				INSERT INTO findings (scan_id, line_no, template_id, name, severity, host, matched_at)
				VALUES ($1, 1, 't', 'n', 'medium', 'a.example.test', 'https://a.example.test')`, scanID)
			Expect(err).ToNot(HaveOccurred())

			_, err = db.SQL().Exec(`DELETE FROM scans WHERE id = $1`, scanID)
			Expect(err).ToNot(HaveOccurred())

			var remaining int
			Expect(db.SQL().QueryRow(`SELECT count(*) FROM findings`).Scan(&remaining)).To(Succeed())
			Expect(remaining).To(Equal(0))
		})
	})
})
