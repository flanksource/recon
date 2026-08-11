package schema_test

import (
	"testing"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	recondb "github.com/flanksource/recon/internal/db"
	"github.com/flanksource/recon/internal/schema"
)

var _ = Describe("the migration bundle", func() {
	It("loads every declarative and SQL migration", func(ctx SpecContext) {
		fingerprint, err := schema.NewProvisioner().Fingerprint(ctx)
		Expect(err).ToNot(HaveOccurred())
		Expect(fingerprint).ToNot(BeEmpty())
	})
})

// These specs need a real Postgres: the checks, the array quantifiers and the
// expression indexes are all server-side behaviour that no unit test can stand
// in for. dbtest resolves an embedded cluster (or COMMONS_DB_URL) and clones a
// sealed template, so the bundle is applied once rather than per spec.
var _ = Describe("the declarative schema", Ordered, Label("db"), func() {
	var db *dbtest.DB

	BeforeAll(func() {
		// -short is the suite that needs no database, so that a checkout can be
		// verified without provisioning Postgres.
		if testing.Short() {
			Skip("needs a database")
		}
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
			"discoveries", "discovery_hosts",
			"engine_profiles", "findings", "scan_outputs", "scans", "targets", "zones",
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

	It("does not constrain application vocabularies", func() {
		rows, err := db.SQL().Query(`
			SELECT conname
			FROM pg_constraint
			WHERE conname IN (
				'targets_class_enum',
				'targets_profiles_known',
				'discoveries_chain_enum',
				'engine_profiles_kind_enum',
				'scans_phase_enum',
				'findings_severity_enum'
			)
			ORDER BY conname`)
		Expect(err).ToNot(HaveOccurred())
		defer rows.Close()

		var constraints []string
		for rows.Next() {
			var name string
			Expect(rows.Scan(&name)).To(Succeed())
			constraints = append(constraints, name)
		}
		Expect(rows.Err()).ToNot(HaveOccurred())
		Expect(constraints).To(BeEmpty())
	})

	It("removes legacy application vocabulary constraints", func() {
		_, err := db.SQL().Exec(`
			ALTER TABLE targets ADD CONSTRAINT targets_class_enum
				CHECK (class IN ('public', 'prod', 'non-prod', 'internal', 'unclassified', 'deactivated'));
			ALTER TABLE targets ADD CONSTRAINT targets_profiles_known
				CHECK (profiles <@ ARRAY['safe', 'full']::text[]);
			ALTER TABLE discoveries ADD CONSTRAINT discoveries_chain_enum
				CHECK (chain IN ('full', 'targeted', 'explicit'));
			ALTER TABLE engine_profiles ADD CONSTRAINT engine_profiles_kind_enum
				CHECK (kind IN ('discovery', 'scan'));
			ALTER TABLE scans ADD CONSTRAINT scans_phase_enum
				CHECK (phase IN ('idle', 'running', 'done', 'failed', 'cancelled'));
			ALTER TABLE findings ADD CONSTRAINT findings_severity_enum
				CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown'))`)
		Expect(err).ToNot(HaveOccurred())
		_, err = db.SQL().Exec(`
			DELETE FROM schema_migration_scripts
			WHERE scope = $1 AND path = '012_drop_enum_constraints.sql'`, schema.Name)
		Expect(err).ToNot(HaveOccurred())

		handle, err := recondb.Open(GinkgoT().Context(), recondb.Config{URL: db.DSN()})
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(func() { Expect(handle.Close()).To(Succeed()) })

		var remaining int
		Expect(db.SQL().QueryRow(`
			SELECT count(*)
			FROM pg_constraint
			WHERE conname IN (
				'targets_class_enum',
				'targets_profiles_known',
				'discoveries_chain_enum',
				'engine_profiles_kind_enum',
				'scans_phase_enum',
				'findings_severity_enum'
			)`).Scan(&remaining)).To(Succeed())
		Expect(remaining).To(Equal(0))
	})

	It("backfills wall-clock duration for terminal legacy scans", func() {
		var scanID string
		Expect(db.SQL().QueryRow(`
			INSERT INTO scans (
				name, engine, profile, endpoint_count, phase,
				started_at, finished_at, severities
			) VALUES (
				'legacy-duration-scan', 'nuclei', 'safe', 1, 'done',
				'2026-08-10T12:00:00Z', '2026-08-10T12:00:03.250Z', '{}'::jsonb
			) RETURNING id::text`).Scan(&scanID)).To(Succeed())
		_, err := db.SQL().Exec(`
			DELETE FROM schema_migration_scripts
			WHERE scope = $1 AND path = '013_scan_duration.sql'`, schema.Name)
		Expect(err).ToNot(HaveOccurred())

		Expect(schema.Apply(GinkgoT().Context(), db.DSN())).To(Succeed())

		var durationMS int64
		Expect(db.SQL().QueryRow(`SELECT duration_ms FROM scans WHERE id = $1`, scanID).Scan(&durationMS)).To(Succeed())
		Expect(durationMS).To(Equal(int64(3250)))
		_, err = db.SQL().Exec(`DELETE FROM scans WHERE id = $1`, scanID)
		Expect(err).ToNot(HaveOccurred())
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

		It("accepts unclassified IP targets created by discovery", func() {
			Expect(insert("192.0.2.10", "unclassified")).To(Succeed())
			Expect(insert("2001:db8::10", "unclassified")).To(Succeed())
		})

		It("accepts a class outside the application vocabulary", func() {
			Expect(insert("a.example.test", "staging")).To(Succeed())
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

		It("accepts a profile outside the application vocabulary", func() {
			_, err := db.SQL().Exec(
				`INSERT INTO targets (host, class, profiles, tags)
				 VALUES ('a.example.test', 'non-prod', ARRAY['aggressive']::text[], '{}'::text[])`)
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects an empty profiles array", func() {
			_, err := db.SQL().Exec(
				`INSERT INTO targets (host, class, profiles, tags)
				 VALUES ('a.example.test', 'non-prod', '{}'::text[], '{}'::text[])`)
			Expect(err).To(MatchError(ContainSubstring("targets_profiles_nonempty")))
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
