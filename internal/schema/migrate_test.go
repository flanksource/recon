package schema_test

import (
	"testing"
	"time"

	"github.com/flanksource/commons-db/dbtest"
	"github.com/lib/pq"
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
		DeferCleanup(rows.Close)
		for rows.Next() {
			var name string
			Expect(rows.Scan(&name)).To(Succeed())
			tables = append(tables, name)
		}
		Expect(rows.Err()).ToNot(HaveOccurred())

		Expect(tables).To(ConsistOf(
			"checks", "connections", "discoveries", "discovery_hosts",
			"engine_profiles", "finding_resources", "finding_states", "findings",
			"mute_rules", "probe_results", "probes", "resources", "scan_outputs",
			"scans", "targets", "zones",
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
		DeferCleanup(rows.Close)

		var constraints []string
		for rows.Next() {
			var name string
			Expect(rows.Scan(&name)).To(Succeed())
			constraints = append(constraints, name)
		}
		Expect(rows.Err()).ToNot(HaveOccurred())
		Expect(constraints).To(BeEmpty())
	})

	// 012 drops these by name with IF EXISTS, so what is under test is the name
	// rather than the expression. findings_severity_enum constrained a `severity`
	// column that findings no longer has — it became OCSF's severity_id — so it is
	// planted over the column that replaced it. A database that really carries the
	// historical constraint has already run 012 and dropped it; one that has not
	// loses it to the diff instead, since Postgres drops a CHECK along with the
	// column it constrains, and 012's IF EXISTS then finds nothing.
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
				CHECK (severity_id IS NOT NULL)`)
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

	// The upgrade every existing database performs: a table of nuclei-shaped rows
	// with the engine's whole record beside them in `raw`, arriving as OCSF
	// Detection Findings.
	//
	// The other backfill specs re-run one script against the finished schema.
	// This one cannot, because the columns it reads from are the ones the diff
	// drops — so the table is first rewound to the shape it had before this
	// change. That rewind is not a contrivance: it is exactly what a real
	// database looks like when the pre-phase scripts run, and the only state in
	// which 022 and 023 have anything to do.
	//
	// The resources rows are seeded rather than recovered. 016 recovered them
	// from `raw`, and it no longer can: it is a post script, so by the time it
	// runs the diff has dropped the column. Every database that has one has
	// already run it, and one that has not repopulates on its next scan — which
	// is why the link recovery below joins to resources rather than creating any.
	It("upgrades legacy findings into OCSF Detection Findings", func() {
		_, err := db.SQL().Exec(`
			ALTER TABLE findings
				DROP COLUMN check_id, DROP COLUMN engine, DROP COLUMN verdict,
				DROP COLUMN class_uid, DROP COLUMN category_uid, DROP COLUMN type_uid,
				DROP COLUMN activity_id, DROP COLUMN severity_id, DROP COLUMN status_id,
				DROP COLUMN status_code, DROP COLUMN status_detail, DROP COLUMN "time",
				DROP COLUMN finding_info, DROP COLUMN metadata, DROP COLUMN remediation,
				DROP COLUMN cloud, DROP COLUMN vulnerabilities, DROP COLUMN observables,
				DROP COLUMN unmapped, DROP COLUMN evidences, DROP COLUMN evidences_truncated,
				ADD COLUMN template_id text NOT NULL DEFAULT '',
				ADD COLUMN name text NOT NULL DEFAULT '',
				ADD COLUMN severity text NOT NULL DEFAULT 'unknown',
				ADD COLUMN type text NOT NULL DEFAULT '',
				ADD COLUMN matcher_name text,
				ADD COLUMN "timestamp" timestamptz,
				ADD COLUMN raw jsonb,
				ADD COLUMN request text,
				ADD COLUMN response text,
				ADD COLUMN curl text,
				ADD COLUMN extracted text[],
				ADD COLUMN remediation text,
				ADD COLUMN reference text[]`)
		Expect(err).ToNot(HaveOccurred())

		var scanID string
		Expect(db.SQL().QueryRow(`
			INSERT INTO scans (
				name, engine, profile, endpoint_count, phase,
				started_at, finished_at, severities
			) VALUES (
				'legacy-ocsf-upgrade', 'prowler', 'gcp-cis-5-0', 1, 'done',
				'2026-08-11T12:00:00Z', '2026-08-11T12:01:00Z', '{}'::jsonb
			) RETURNING id::text`).Scan(&scanID)).To(Succeed())

		for _, uid := range []string{"bucket-a", "bucket-b"} {
			_, err := db.SQL().Exec(`
				INSERT INTO resources (provider, scope, uid, kind, type, name)
				VALUES ('gcp', 'flanksource-prod', $1, 'cloud-resource',
					'storage.googleapis.com/Bucket', $1)`, uid)
			Expect(err).ToNot(HaveOccurred())
		}

		// A check that failed against two buckets. Only the first was ever
		// linked; the second existed nowhere but `raw`.
		var prowlerID string
		Expect(db.SQL().QueryRow(`
			INSERT INTO findings (
				scan_id, line_no, template_id, name, severity, host, matched_at,
				type, matcher_name, tags, remediation, reference, "timestamp", raw
			) VALUES (
				$1::uuid, 1, 'gcp/bucket_public', 'Bucket is public', 'high',
				'flanksource-prod', 'bucket-a', 'prowler', 'MANUAL',
				ARRAY['cis']::text[], 'Make the bucket private',
				ARRAY['https://example.test/bucket']::text[],
				NULL, $2::jsonb
			) RETURNING id::text`, scanID, `{
				"cloud": {"provider": "gcp", "account": {"uid": "flanksource-prod"}},
				"finding_info": {"desc": "Objects in this bucket are readable by allUsers."},
				"risk_details": "Anyone on the internet can read the objects.",
				"time_dt": "2026-08-11T15:00:30.500000",
				"status_code": "MANUAL",
				"unmapped": {
					"provider": "gcp",
					"compliance": {"CIS-5.0": ["5.1"]}
				},
				"resources": [
					{"uid": "bucket-a", "name": "logs"},
					{"uid": "bucket-b", "name": "backups"}
				]
			}`).Scan(&prowlerID)).To(Succeed())

		// Its own run, because `type` did not mean the same thing in both: for
		// prowler it named the engine and for nuclei the protocol a template
		// spoke, which is the conflation the upgrade has to see through.
		var nucleiScanID string
		Expect(db.SQL().QueryRow(`
			INSERT INTO scans (
				name, engine, profile, endpoint_count, phase,
				started_at, finished_at, severities
			) VALUES (
				'legacy-ocsf-upgrade-nuclei', 'nuclei', 'safe', 1, 'done',
				'2026-08-11T12:00:00Z', '2026-08-11T12:01:00Z', '{}'::jsonb
			) RETURNING id::text`).Scan(&nucleiScanID)).To(Succeed())

		// The four columns that only nuclei ever filled, and that OCSF models as
		// one evidence entry.
		var nucleiID string
		Expect(db.SQL().QueryRow(`
			INSERT INTO findings (
				scan_id, line_no, template_id, name, severity, host, matched_at,
				type, tags, request, response, curl, extracted, "timestamp", raw
			) VALUES (
				$1::uuid, 2, 'exposed-panel', 'Exposed admin panel', 'medium',
				'app.example.test', 'https://app.example.test/admin', 'http',
				'{}'::text[], 'GET /admin HTTP/1.1', 'HTTP/1.1 200 OK',
				'curl -s https://app.example.test/admin',
				ARRAY['v1.2.3']::text[], '2026-08-11T12:00:40Z', $2::jsonb
			) RETURNING id::text`, nucleiScanID, `{
				"type": "http",
				"info": {"reference": ["https://example.test/panel", "https://example.test/other"]}
			}`).Scan(&nucleiID)).To(Succeed())

		_, err = db.SQL().Exec(`
			DELETE FROM schema_migration_scripts
			WHERE scope = $1 AND path IN (
				'016_backfill_resources.sql', '018_check_catalogue.sql',
				'021_finding_verdict.sql', '022_finding_resources.sql',
				'023_ocsf_findings.sql', '025_repair_ocsf_engine.sql')`, schema.Name)
		Expect(err).ToNot(HaveOccurred())

		Expect(schema.Apply(GinkgoT().Context(), db.DSN())).To(Succeed())

		var (
			checkID, engine, verdict         string
			severityID, classUID, activityID int
			typeUID                          int64
			title, desc, kind                string
			risk                             string
			statusCode, provider             string
			remediationDesc, remediationRef  string
			profile                          string
		)
		Expect(db.SQL().QueryRow(`
			SELECT check_id, engine, verdict,
			       severity_id, class_uid, activity_id, type_uid,
			       finding_info ->> 'title', finding_info ->> 'desc',
			       finding_info -> 'types' ->> 0, risk_details,
			       status_code, cloud ->> 'provider',
			       remediation ->> 'desc', remediation -> 'references' ->> 0,
			       metadata -> 'profiles' ->> 0
			FROM findings WHERE id = $1::uuid`, prowlerID).
			Scan(&checkID, &engine, &verdict,
				&severityID, &classUID, &activityID, &typeUID,
				&title, &desc, &kind, &risk,
				&statusCode, &provider,
				&remediationDesc, &remediationRef, &profile)).To(Succeed())

		// Identity moved rather than changed: these are what the lifecycle, the
		// catalogue and every stored mute rule key on.
		Expect(checkID).To(Equal("gcp/bucket_public"))
		Expect(engine).To(Equal("prowler"))

		Expect(classUID).To(Equal(2004), "detection_finding")
		Expect(activityID).To(Equal(1), "create")
		Expect(typeUID).To(Equal(int64(200401)), "class_uid * 100 + activity_id")
		Expect(severityID).To(Equal(4), "OCSF numbers high 4; recon called it 'high'")

		// What triage needed and could previously reach only by digging through
		// the blob, differently per engine.
		Expect(title).To(Equal("Bucket is public"))
		// What was found and what it means are two facts with two homes. The
		// upgrade used to write the risk statement into the description, which
		// is where a reader looks for the check's own words.
		Expect(desc).To(Equal("Objects in this bucket are readable by allUsers."))
		Expect(risk).To(Equal("Anyone on the internet can read the objects."))

		// The timestamp column was NULL for every prowler row ever stored: it
		// spells time_dt without a zone, and the ingest that wrote the column
		// parsed it as RFC3339, which refuses one. Reading the record recovers
		// what the column never held.
		var stamped time.Time
		Expect(db.SQL().QueryRow(
			`SELECT "time" FROM findings WHERE id = $1::uuid`, prowlerID).
			Scan(&stamped)).To(Succeed())
		Expect(stamped).To(BeTemporally("==",
			time.Date(2026, 8, 11, 15, 0, 30, 500_000_000, time.Local)))
		Expect(kind).To(Equal("cis"), "recon's tags, projected into finding_info.types")
		Expect(remediationDesc).To(Equal("Make the bucket private"))
		Expect(remediationRef).To(Equal("https://example.test/bucket"))
		Expect(provider).To(Equal("gcp"))
		Expect(profile).To(Equal("cloud"),
			"prowler declares the profile that makes cloud a required attribute")

		// matcher_name held prowler's OCSF status_code, and 021 reads the manual
		// verdict back out of the column it moved to.
		Expect(statusCode).To(Equal("MANUAL"))
		Expect(verdict).To(Equal("manual"))

		rows, err := db.SQL().Query(`
			SELECT r.uid FROM finding_resources fr
			JOIN resources r ON r.id = fr.resource_id
			WHERE fr.finding_id = $1::uuid
			ORDER BY fr.ordinal`, prowlerID)
		Expect(err).ToNot(HaveOccurred())
		DeferCleanup(rows.Close)

		var linked []string
		for rows.Next() {
			var uid string
			Expect(rows.Scan(&uid)).To(Succeed())
			linked = append(linked, uid)
		}
		Expect(rows.Err()).ToNot(HaveOccurred())
		// In the order the record named them: the first is the subject the
		// verdict is about, and the second had no home at all before.
		Expect(linked).To(Equal([]string{"bucket-a", "bucket-b"}))

		var request, response, curl, extracted string
		Expect(db.SQL().QueryRow(`
			SELECT evidences -> 0 -> 'http_request' ->> 'args',
			       evidences -> 0 -> 'http_response' ->> 'message',
			       evidences -> 0 -> 'data' ->> 'curl',
			       evidences -> 0 -> 'data' -> 'extracted' ->> 0
			FROM findings WHERE id = $1::uuid`, nucleiID).
			Scan(&request, &response, &curl, &extracted)).To(Succeed())
		Expect(request).To(Equal("GET /admin HTTP/1.1"))
		Expect(response).To(Equal("HTTP/1.1 200 OK"))
		Expect(curl).To(Equal("curl -s https://app.example.test/admin"))
		Expect(extracted).To(Equal("v1.2.3"))

		// The column named `type` said "http" for this row, which is the
		// protocol — the run says which scanner produced it, and that is what
		// `engine` means. Reading the column instead labelled a whole nuclei run
		// "http", or nothing at all when the host never answered.
		var nucleiEngine, protocol, srcURL string
		var strayType *string
		Expect(db.SQL().QueryRow(`
			SELECT engine, unmapped ->> 'protocol', unmapped ->> 'type',
			       finding_info ->> 'src_url'
			FROM findings WHERE id = $1::uuid`, nucleiID).
			Scan(&nucleiEngine, &protocol, &strayType, &srcURL)).To(Succeed())
		Expect(nucleiEngine).To(Equal("nuclei"))
		Expect(protocol).To(Equal("http"), "under the key the adapter writes it as")
		Expect(strayType).To(BeNil(), "the same fact must not also be spelled `type`")
		// One link, not the list rendered as JSON text into a field the schema
		// types as a URL.
		Expect(srcURL).To(Equal("https://example.test/panel"))

		// The escape hatch carries what each adapter puts there and nothing
		// else. Copying the rest of the record would move the verbatim payload
		// from `raw` to `unmapped` and change nothing but its name — the same
		// blob, every attribute stored twice beside its own column.
		var nucleiKeys, prowlerKeys []string
		Expect(db.SQL().QueryRow(`
			SELECT ARRAY(SELECT jsonb_object_keys(unmapped) ORDER BY 1)
			FROM findings WHERE id = $1::uuid`, nucleiID).
			Scan(pq.Array(&nucleiKeys))).To(Succeed())
		Expect(nucleiKeys).To(Equal([]string{"protocol"}))

		Expect(db.SQL().QueryRow(`
			SELECT ARRAY(SELECT jsonb_object_keys(unmapped) ORDER BY 1)
			FROM findings WHERE id = $1::uuid`, prowlerID).
			Scan(pq.Array(&prowlerKeys))).To(Succeed())
		// Kept because prowler's checks are organised by framework, and "which
		// CIS control does this fail" is what a compliance audit is asking.
		Expect(prowlerKeys).To(Equal([]string{"compliance"}))

		// The catalogue describes itself from the OCSF columns now, and must
		// describe a check the same way a fresh run would.
		var catalogueName, catalogueSeverity, catalogueRemediation string
		Expect(db.SQL().QueryRow(`
			SELECT name, severity, remediation FROM checks
			WHERE engine = 'prowler' AND check_id = 'gcp/bucket_public'`).
			Scan(&catalogueName, &catalogueSeverity, &catalogueRemediation)).To(Succeed())
		Expect(catalogueName).To(Equal("Bucket is public"))
		Expect(catalogueSeverity).To(Equal("high"))
		Expect(catalogueRemediation).To(Equal("Make the bucket private"))

		// The point of the exercise: none of the old shape survives.
		var legacy int
		Expect(db.SQL().QueryRow(`
			SELECT count(*) FROM information_schema.columns
			WHERE table_name = 'findings' AND column_name IN (
				'raw', 'matcher_name', 'template_id', 'severity', 'timestamp',
				'request', 'response', 'curl', 'extracted', 'reference',
				'remediation_text')`).Scan(&legacy)).To(Succeed())
		Expect(legacy).To(BeZero())

		_, err = db.SQL().Exec(
			`DELETE FROM scans WHERE id = ANY(ARRAY[$1, $2]::uuid[])`, scanID, nucleiScanID)
		Expect(err).ToNot(HaveOccurred())
		_, err = db.SQL().Exec(`DELETE FROM resources`)
		Expect(err).ToNot(HaveOccurred())
		_, err = db.SQL().Exec(`DELETE FROM checks`)
		Expect(err).ToNot(HaveOccurred())
	})

	// A rule's expression is CEL over the finding's own JSON projection, so
	// reshaping the record reshaped the vocabulary. These specs are the other
	// half of that: what the upgrade rewrites, and what it refuses to guess at.
	Describe("stored mute expressions", func() {
		rewind := func() {
			_, err := db.SQL().Exec(`
				DELETE FROM schema_migration_scripts
				WHERE scope = $1 AND path = '024_mute_expr_ocsf.sql'`, schema.Name)
			Expect(err).ToNot(HaveOccurred())
		}
		store := func(name, expression string) {
			_, err := db.SQL().Exec(
				`INSERT INTO mute_rules (name, expr) VALUES ($1, $2)`, name, expression)
			Expect(err).ToNot(HaveOccurred())
		}

		AfterEach(func() {
			_, err := db.SQL().Exec(`DELETE FROM mute_rules`)
			Expect(err).ToNot(HaveOccurred())
			rewind()
			Expect(schema.Apply(GinkgoT().Context(), db.DSN())).To(Succeed())
		})

		It("moves every one-to-one path onto its OCSF name", func() {
			store("legacy-paths",
				`finding.templateId == "gcp/bucket_public" && finding.type == "prowler" `+
					`&& finding.name.contains("public") `+
					`&& finding.raw.resources[0].uid == "bucket-a" `+
					`&& finding.raw.cloud.account.uid == "1234" `+
					`&& finding.raw.info.description != "" `+
					`&& finding.remediation != "" && finding.reference.size() > 0`)
			rewind()

			Expect(schema.Apply(GinkgoT().Context(), db.DSN())).To(Succeed())

			var rewritten string
			Expect(db.SQL().QueryRow(
				`SELECT expr FROM mute_rules WHERE name = 'legacy-paths'`).
				Scan(&rewritten)).To(Succeed())
			Expect(rewritten).To(Equal(
				`finding.checkId == "gcp/bucket_public" && finding.engine == "prowler" ` +
					`&& finding.finding_info.title.contains("public") ` +
					`&& finding.resources[0].uid == "bucket-a" ` +
					`&& finding.cloud.account.uid == "1234" ` +
					`&& finding.finding_info.desc != "" ` +
					`&& finding.remediation.desc != "" && finding.remediation.references.size() > 0`))
		})

		// Editing a committed script makes it re-run on every database, so a
		// rewrite that is not a fixed point corrupts what it already fixed.
		It("leaves an already-rewritten expression alone", func() {
			store("already-ocsf", `finding.remediation.desc != "" && finding.severity_id >= 4`)
			rewind()

			Expect(schema.Apply(GinkgoT().Context(), db.DSN())).To(Succeed())

			var unchanged string
			Expect(db.SQL().QueryRow(
				`SELECT expr FROM mute_rules WHERE name = 'already-ocsf'`).
				Scan(&unchanged)).To(Succeed())
			Expect(unchanged).To(Equal(`finding.remediation.desc != "" && finding.severity_id >= 4`))
		})

		// severity was a string and is an integer; a rewrite would have to invent
		// the comparison, and one that guessed wrong would suppress the wrong
		// findings silently.
		DescribeTable("refuses to guess at a path that did not survive",
			func(expression string) {
				store("untranslatable", expression)
				rewind()

				err := schema.Apply(GinkgoT().Context(), db.DSN())
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("untranslatable"))
				Expect(err.Error()).To(ContainSubstring("no longer have"))
			},
			Entry("severity as a string", `finding.severity == "high"`),
			Entry("timestamp as a string", `finding.timestamp.startsWith("2026")`),
			Entry("matcherName, which meant four things", `finding.matcherName == "FAIL"`),
			Entry("a request column that is an evidence entry now", `finding.request.contains("GET")`),
			Entry("an engine key with no modelled home", `finding.raw.template_path != ""`),
			Entry("an info key the upgrade dropped", `finding.raw.info.author == "pdteam"`),
		)
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
				`INSERT INTO targets (id, host, class, profiles, tags, reason)
				 VALUES ($1, $1, $2, ARRAY['scan:nuclei:safe']::text[], '{}'::text[], $3)`,
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

		It("creates the provider credentials jsonb column", func() {
			var dataType string
			Expect(db.SQL().QueryRow(`
				SELECT data_type FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'targets' AND column_name = 'credentials'
			`).Scan(&dataType)).To(Succeed())
			Expect(dataType).To(Equal("jsonb"))
		})

		It("keeps credentials off host rows", func() {
			_, err := db.SQL().Exec(`
				INSERT INTO targets (id, host, class, profiles, tags, credentials)
				VALUES (
					'a.example.test', 'a.example.test', 'non-prod',
					ARRAY['scan:nuclei:safe']::text[], '{}'::text[],
					'{"envVars":[{"name":"TOKEN","value":"not-allowed"}]}'::jsonb
				)`)
			Expect(err).To(MatchError(ContainSubstring("targets_kind_shape")))
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
				`INSERT INTO targets (id, host, class, profiles, tags)
				 VALUES ('a.example.test', 'a.example.test', 'non-prod', ARRAY['scan:nuclei:aggressive']::text[], '{}'::text[])`)
			Expect(err).ToNot(HaveOccurred())
		})

		It("rejects an empty profiles array", func() {
			_, err := db.SQL().Exec(
				`INSERT INTO targets (id, host, class, profiles, tags)
				 VALUES ('a.example.test', 'a.example.test', 'non-prod', '{}'::text[], '{}'::text[])`)
			Expect(err).To(MatchError(ContainSubstring("targets_profiles_nonempty")))
		})

		DescribeTable("bounds curated ports",
			func(ports string, succeeds bool) {
				_, err := db.SQL().Exec(
					`INSERT INTO targets (id, host, class, profiles, tags, ports)
					 VALUES ('a.example.test', 'a.example.test', 'non-prod', ARRAY['scan:nuclei:safe']::text[], '{}'::text[], ` + ports + `)`)
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
				INSERT INTO findings (
					scan_id, line_no, check_id, engine, severity_id, type_uid,
					host, matched_at, finding_info
				)
				VALUES ($1, 1, 't', 'nuclei', 3, 200401, 'a.example.test',
					'https://a.example.test', '{"uid": "t", "title": "n"}'::jsonb)`, scanID)
			Expect(err).ToNot(HaveOccurred())

			_, err = db.SQL().Exec(`DELETE FROM scans WHERE id = $1`, scanID)
			Expect(err).ToNot(HaveOccurred())

			var remaining int
			Expect(db.SQL().QueryRow(`SELECT count(*) FROM findings`).Scan(&remaining)).To(Succeed())
			Expect(remaining).To(Equal(0))
		})
	})
})
