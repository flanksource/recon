package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

// The lifecycle: which of a run's findings the next run resolves.
//
// This is the whole reason resources exist. Two runs of the same profile an
// hour and forty-four minutes apart reported 65 failures and then 49 — sixteen
// problems genuinely fixed, none new — and both runs' rows sit in `findings`
// side by side with nothing distinguishing the sixteen that are gone. Every
// spec here is one way that difference can be got wrong, and most of them are
// ways of getting it wrong that silently report a clean estate.
var _ = Describe("what a run makes true", Ordered, Label("db"), func() {
	var (
		db  *dbtest.DB
		st  *store.Store
		ctx context.Context

		run int
	)

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_lifecycle",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
	})

	// Each spec starts from an empty estate. The ledger is deliberately durable
	// across runs, so without this a spec would inherit the previous one's
	// history and the failures would depend on declaration order.
	BeforeEach(func() {
		Expect(db.Gorm().Exec(`DELETE FROM scans`).Error).To(Succeed())
		Expect(db.Gorm().Exec(`DELETE FROM resources`).Error).To(Succeed())
	})

	const (
		account  = "flanksource-prod"
		bucket   = "storage.googleapis.com/Bucket"
		check    = "gcp/bucket_public_access"
		another  = "gcp/bucket_versioning_enabled"
		provider = "gcp"
	)

	// resource names one subject and what the run concluded about it.
	resource := func(uid string, passed ...string) api.Resource {
		return api.Resource{
			Provider: provider, Scope: account, UID: uid,
			Kind: api.KindCloudResource, Type: bucket, Name: uid,
			Service: "storage", Passed: passed,
		}
	}

	failure := func(line int, uid, checkID string) api.Finding {
		return api.Finding{
			LineNo: line, TemplateID: checkID, Name: checkID,
			Severity: api.SeverityHigh, Host: account, MatchedAt: uid,
			Resources: []api.ResourceRef{{Provider: provider, Scope: account, UID: uid, Name: uid, Type: bucket}},
		}
	}

	// scan finalizes one run and returns nothing: every spec asserts on the
	// ledger the run left, never on the run itself.
	type outcome struct {
		phase        api.Phase
		passRecorded bool
		resources    []api.Resource
		findings     []api.Finding
		muted        []api.Finding
		mutedBy      map[string][]int
	}

	scan := func(result outcome) {
		GinkgoHelper()
		run++
		started := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC).Add(time.Duration(run) * time.Hour)
		row, err := st.CreateScan(ctx, models.Scan{
			Name:   fmt.Sprintf("prowler-cis-2026082%d", run),
			Engine: "prowler", Profile: "gcp-cis-5-0",
			Phase: string(api.PhaseRunning), StartedAt: started,
		})
		Expect(err).ToNot(HaveOccurred())

		finished := started.Add(time.Minute)
		exitCode := 0
		stats := api.ScanStats{PassRecorded: result.passRecorded}
		phase := result.phase
		if phase == "" {
			phase = api.PhaseDone
		}
		row.Phase = string(phase)
		row.FinishedAt = &finished
		row.ExitCode = &exitCode
		row.Stats = models.Wrap(&stats)

		Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
			Scan: row, Findings: result.findings, Resources: result.resources,
			Muted: result.muted, MutedBy: result.mutedBy,
		})).To(Succeed())
	}

	// state reads back the one ledger row a spec is about.
	state := func(uid, checkID string) models.FindingState {
		GinkgoHelper()
		var rows []models.FindingState
		Expect(db.Gorm().Raw(`
			SELECT s.* FROM finding_states s
			JOIN resources r ON r.id = s.resource_id
			WHERE r.uid = ? AND s.check_id = ?`, uid, checkID).Scan(&rows).Error).To(Succeed())
		Expect(rows).To(HaveLen(1), "expected exactly one ledger row for %s/%s", uid, checkID)
		return rows[0]
	}

	states := func() []models.FindingState {
		GinkgoHelper()
		var rows []models.FindingState
		Expect(db.Gorm().Raw(`SELECT * FROM finding_states`).Scan(&rows).Error).To(Succeed())
		return rows
	}

	resourceState := func(uid string) string {
		GinkgoHelper()
		var value string
		Expect(db.Gorm().Raw(`SELECT state FROM resources WHERE uid = ?`, uid).
			Scan(&value).Error).To(Succeed())
		return value
	}

	Describe("a check that fails", func() {
		It("opens, and carries the evidence", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(1, "logs", check)},
			})

			opened := state("logs", check)
			Expect(opened.Status).To(Equal(api.StatusOpen))
			Expect(opened.Severity).To(Equal(string(api.SeverityHigh)))
			Expect(opened.Occurrences).To(Equal(1))
			Expect(opened.FindingID).ToNot(BeNil(), "an open state points at the finding proving it")
			Expect(opened.Reason).To(BeNil())
		})

		// The two fields that answer "how long has this been wrong". Both are
		// one careless EXCLUDED away from resetting on every scan, which would
		// make a six-month-old problem look like it appeared this morning.
		It("keeps its age when a later run finds it still failing", func() {
			for line := 1; line <= 2; line++ {
				scan(outcome{
					passRecorded: true,
					resources:    []api.Resource{resource("logs")},
					findings:     []api.Finding{failure(line, "logs", check)},
				})
			}

			still := state("logs", check)
			Expect(still.Status).To(Equal(api.StatusOpen))
			Expect(still.Occurrences).To(Equal(2), "occurrences counts runs, not findings")
			Expect(still.FirstSeen).To(BeTemporally("<", still.LastSeen))
			Expect(*still.OpenScanID).To(Equal(*still.FirstScanID),
				"failing since the first run, not since the most recent one")
		})

		// The single most likely production crash in the design: nuclei fires
		// several matchers at one URL routinely, and two rows reaching one ON
		// CONFLICT target makes Postgres abort the entire finalize transaction
		// — losing the run's terminal status along with all of its evidence.
		It("does not conflict with itself when one run reports it twice", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings: []api.Finding{
					failure(1, "logs", check),
					failure(2, "logs", check),
				},
			})

			Expect(state("logs", check).Occurrences).To(Equal(1),
				"one run reporting a pair twice is still one occurrence")
		})
	})

	Describe("a check that passes", func() {
		// The only resolution that is a fact rather than an inference.
		It("resolves what it previously failed", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(1, "logs", check)},
			})
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", check)},
			})

			fixed := state("logs", check)
			Expect(fixed.Status).To(Equal(api.StatusResolved))
			Expect(*fixed.Reason).To(Equal(api.ReasonPassed))
			Expect(fixed.ResolvedAt).ToNot(BeNil())
			Expect(fixed.FindingID).To(BeNil(), "the evidence is gone because the problem is")
		})

		// 141 of one report's 190 verdicts are passes. Recording only failures
		// is how "this bucket has been checked forty times and passed every
		// time" — the compliance posture — ends up with nowhere to live.
		It("is recorded even when it has never failed", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", check)},
			})

			clean := state("logs", check)
			Expect(clean.Status).To(Equal(api.StatusResolved))
			Expect(*clean.Reason).To(Equal(api.ReasonPassed))
			Expect(clean.Occurrences).To(BeZero(), "it has never been reported failing")
		})
	})

	Describe("what a run no longer mentions", func() {
		It("resolves a check that went silent about a resource it still sees", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", another)},
				findings:     []api.Finding{failure(1, "logs", check)},
			})
			// The same resource, still seen, still reporting `another` — but
			// this run says nothing at all about `check`.
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", another, check)},
			})

			Expect(*state("logs", check).Reason).To(Equal(api.ReasonPassed))
		})

		It("resolves and marks absent a resource it no longer sees", func() {
			scan(outcome{
				passRecorded: true,
				resources: []api.Resource{
					resource("logs", another, check),
					resource("backups", another),
				},
				findings: []api.Finding{failure(1, "backups", check)},
			})
			// The bucket was deleted. This run covered the same account, ran
			// the same check, and enumerated the same type — it saw `logs`, so
			// it did look at buckets — and never mentioned `backups`.
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", another, check)},
			})

			gone := state("backups", check)
			Expect(gone.Status).To(Equal(api.StatusResolved))
			Expect(*gone.Reason).To(Equal(api.ReasonResourceAbsent),
				"a vanished resource is a different fact from a check that stopped applying")
			Expect(resourceState("backups")).To(Equal(api.ResourceAbsent))
			Expect(resourceState("logs")).To(Equal(api.ResourcePresent))
		})

		// The difference between an inference and a guess. A run filtered to one
		// check family enumerates that family's resources and nothing else, so
		// a bucket missing from an apikeys run is not a deleted bucket — it is
		// a bucket nobody asked about. Seeing one bucket is what proves the run
		// enumerated buckets at all.
		It("does not call a resource absent when it never enumerated that type", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", check)},
			})

			key := api.Resource{
				Provider: provider, Scope: account, UID: "prod-key",
				Kind: api.KindCloudResource, Type: "apikeys.googleapis.com/Key",
				Name: "prod-key", Service: "apikeys", Passed: []string{check},
			}
			scan(outcome{passRecorded: true, resources: []api.Resource{key}})

			Expect(resourceState("logs")).To(Equal(api.ResourcePresent),
				"this run looked at keys, so it has said nothing about buckets")
		})

		// Scoping by observed checks is what makes `--check apikeys_*` leave
		// compute findings alone. Without it, every filtered run reports the
		// rest of the estate as fixed.
		It("leaves a check the run never ran alone", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings: []api.Finding{
					failure(1, "logs", check),
					failure(2, "logs", another),
				},
			})
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", check)},
			})

			Expect(state("logs", check).Status).To(Equal(api.StatusResolved))
			Expect(state("logs", another).Status).To(Equal(api.StatusOpen),
				"this run never ran that check, so it has said nothing about it")
		})

		// And scoping by observed account is what makes a run over one project
		// leave the other alone.
		It("leaves another account alone", func() {
			const elsewhere = "workload-prod-eu-02"
			other := func(uid string, passed ...string) api.Resource {
				built := resource(uid, passed...)
				built.Scope = elsewhere
				return built
			}
			elsewhereFails := failure(2, "logs", check)
			elsewhereFails.Host = elsewhere
			elsewhereFails.Resources[0].Scope = elsewhere

			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs"), other("logs")},
				findings:     []api.Finding{failure(1, "logs", check), elsewhereFails},
			})
			// Both accounts hold a bucket called `logs`, which is exactly why
			// scope is in the natural key.
			Expect(states()).To(HaveLen(2))

			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", check)},
			})

			var open, resolved int
			for _, row := range states() {
				if row.Status == api.StatusOpen {
					open++
				} else {
					resolved++
				}
			}
			Expect(open).To(Equal(1), "the account this run never covered is untouched")
			Expect(resolved).To(Equal(1))
		})
	})

	// The mass-resolve guard, and the reason a truncated run cannot report a
	// clean estate. Both halves matter: a run that stopped early may not resolve
	// from silence, but the verdicts it did make are still statements it made.
	Describe("a run that did not finish", func() {
		DescribeTable("resolves nothing from silence",
			func(phase api.Phase) {
				scan(outcome{
					passRecorded: true,
					resources:    []api.Resource{resource("logs", another)},
					findings:     []api.Finding{failure(1, "logs", check)},
				})
				scan(outcome{
					phase: phase, passRecorded: true,
					resources: []api.Resource{resource("logs", another)},
				})

				Expect(state("logs", check).Status).To(Equal(api.StatusOpen))
			},
			Entry("cancelled", api.PhaseCancelled),
			Entry("failed", api.PhaseFailed),
		)

		It("still resolves what it proved before it stopped", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(1, "logs", check)},
			})
			// Cancelling a run truncates the statements it made. It does not
			// falsify the ones it had already made.
			scan(outcome{
				phase: api.PhaseCancelled, passRecorded: true,
				resources: []api.Resource{resource("logs", check)},
			})

			Expect(*state("logs", check).Reason).To(Equal(api.ReasonPassed))
		})
	})

	// nuclei and trivy report no passes: a template that matched nothing did
	// not pass. Extending the PassRecorded doctrine from run statistics to the
	// lifecycle is what stops an ageing open finding being read as a fixed one.
	It("leaves an engine that reports no passes open, however long ago", func() {
		scan(outcome{
			resources: []api.Resource{resource("logs")},
			findings:  []api.Finding{failure(1, "logs", check)},
		})
		scan(outcome{resources: []api.Resource{resource("logs")}})

		stale := state("logs", check)
		Expect(stale.Status).To(Equal(api.StatusOpen),
			"nobody re-confirmed it, which is not the same as it being fixed")
		Expect(stale.LastSeen).To(BeTemporally("==", stale.LastOpenAt.UTC()))
	})

	Describe("a finding a rule muted", func() {
		// mute.Apply drops the rows before persistence, so without the Dropped
		// list a muted check keeps whatever state it had — open, with an ageing
		// last_seen — and reads as a problem nobody is looking at rather than
		// one somebody accepted.
		It("is recorded as muted, naming the rule, with no findings row", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(1, "logs", check)},
			})
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				muted:        []api.Finding{failure(1, "logs", check)},
				mutedBy:      map[string][]int{"accepted-public-logs": {1}},
			})

			accepted := state("logs", check)
			Expect(accepted.Status).To(Equal(api.StatusMuted))
			Expect(*accepted.Reason).To(Equal("mute:accepted-public-logs"))
			Expect(accepted.FindingID).To(BeNil())

			var findings int64
			Expect(db.Gorm().Raw(`SELECT count(*) FROM findings`).Scan(&findings).Error).To(Succeed())
			Expect(findings).To(Equal(int64(1)),
				"only the first run's finding: a muted finding is never written")
		})
	})

	// Two runs, two subjects, one uid. This is why scope is in the natural key
	// and why the whole design refuses to key on uid alone.
	It("keeps one row per subject however many runs report it", func() {
		for line := 1; line <= 3; line++ {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(line, "logs", check)},
			})
		}

		var resources int64
		Expect(db.Gorm().Raw(`SELECT count(*) FROM resources`).Scan(&resources).Error).To(Succeed())
		Expect(resources).To(Equal(int64(1)))
		Expect(states()).To(HaveLen(1))
	})

	// A run that arrives late, is retried, or contradicts itself.
	//
	// The ledger records what is true now, so every writer has to refuse a run
	// older than the one already recorded, and refuse to let a verdict erase a
	// failure the same run reported. upsertResources has always guarded both;
	// the reconciliation statements did not, and the failure mode is a finding
	// row sitting in the database behind a ledger that says the check passed.
	Describe("a run that arrives out of order or contradicts itself", func() {
		// finalize runs one scan with an explicit finish time, because the scan
		// helper above always moves forward and these specs need to go back.
		finalize := func(name string, finished time.Time, result outcome) models.Scan {
			GinkgoHelper()
			row, err := st.CreateScan(ctx, models.Scan{
				Name: name, Engine: "prowler", Profile: "gcp-cis-5-0",
				Phase: string(api.PhaseRunning), StartedAt: finished.Add(-time.Minute),
			})
			Expect(err).ToNot(HaveOccurred())

			phase := result.phase
			if phase == "" {
				phase = api.PhaseDone
			}
			exitCode := 0
			stats := api.ScanStats{PassRecorded: result.passRecorded}
			row.Phase = string(phase)
			row.FinishedAt = &finished
			row.ExitCode = &exitCode
			row.Stats = models.Wrap(&stats)

			Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
				Scan: row, Findings: result.findings, Resources: result.resources,
				Muted: result.muted, MutedBy: result.mutedBy,
			})).To(Succeed())
			return row
		}

		noon := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

		// Prowler synthesises an account-level resource for a record that names
		// none, so two records differing only by region collapse onto one
		// (resource, check) pair. One says PASS and one says FAIL, and the
		// verdict runs after the open — so without a guard the run resolves the
		// failure it just recorded.
		It("keeps a failure that the same run also reported as a pass", func() {
			finalize("prowler-cis-contradiction", noon, outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", check)},
				findings:     []api.Finding{failure(1, "logs", check)},
			})

			failing := state("logs", check)
			Expect(failing.Status).To(Equal(api.StatusOpen))
			Expect(failing.FindingID).ToNot(BeNil(), "the evidence must stay attached")
			Expect(failing.Reason).To(BeNil())
		})

		It("does not let a replayed older run rewrite the current status", func() {
			finalize("prowler-cis-newer", noon, outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(1, "logs", check)},
			})
			// The same check passing, reported by a run that finished an hour
			// earlier: an artifact imported after the run that superseded it.
			finalize("prowler-cis-older", noon.Add(-time.Hour), outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", check)},
			})

			stale := state("logs", check)
			Expect(stale.Status).To(Equal(api.StatusOpen),
				"an older run cannot resolve what a newer one found failing")
			Expect(stale.LastSeen).To(BeTemporally("==", noon))
		})

		// The findings rows outlive the first finalize, so a second one re-reads
		// and re-opens them even when it is handed nothing.
		It("counts a run once however many times it is finalized", func() {
			row := finalize("prowler-cis-retry", noon, outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(1, "logs", check)},
			})
			Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
				Scan: row, Resources: []api.Resource{resource("logs")},
			})).To(Succeed())

			Expect(state("logs", check).Occurrences).To(Equal(1),
				"occurrences counts runs that reported it failing, not finalize attempts")
		})
	})

	// Absence is judged within one engine's own view, and the row that view is
	// read from is shared.
	//
	// `resources` is keyed on (provider, scope, uid) and deliberately not on the
	// engine, so a resource two engines both describe is one row. A scalar
	// `engine` column was therefore whichever engine finalized last, and
	// markAbsentSQL reads it to decide whose view it may judge — so whichever
	// engine ran first stopped being able to see its own resource at all.
	It("lets every engine that described a resource judge its absence", func() {
		other := func(engine string, at time.Time, resources []api.Resource) {
			GinkgoHelper()
			row, err := st.CreateScan(ctx, models.Scan{
				Name: engine + "-shared-" + at.Format("150405"), Engine: engine,
				Profile: "shared", Phase: string(api.PhaseRunning), StartedAt: at,
			})
			Expect(err).ToNot(HaveOccurred())
			finished := at.Add(time.Minute)
			stats := api.ScanStats{PassRecorded: true}
			row.Phase = string(api.PhaseDone)
			row.FinishedAt = &finished
			row.Stats = models.Wrap(&stats)
			Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
				Scan: row, Resources: resources,
			})).To(Succeed())
		}

		shared := resource("logs", check)
		noon := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
		other("prowler", noon, []api.Resource{shared})
		// trivy describes the same subject afterwards, which used to take the
		// row out of prowler's view for good.
		other("trivy", noon.Add(time.Hour), []api.Resource{shared})

		// unnest so the driver hands back one row per element: scanning the
		// column itself yields the array literal as a single string.
		var engines []string
		Expect(db.Gorm().Raw(`SELECT unnest(engines) FROM resources WHERE uid = ?`, "logs").
			Scan(&engines).Error).To(Succeed())
		Expect(engines).To(ConsistOf("prowler", "trivy"))

		// A later prowler run over the same account that no longer sees it.
		other("prowler", noon.Add(2*time.Hour), []api.Resource{
			resource("archive", check),
		})
		Expect(resourceState("logs")).To(Equal(api.ResourceAbsent))
	})

	// Accepting a finding that already exists.
	//
	// Muting was an ingest-time filter and nothing else, so a rule created in the
	// UI did nothing until the next run of that engine — a week, for a weekly
	// compliance profile — and an operator who had just accepted a finding
	// watched it stay open. Deleting a rule was the mirror image.
	Describe("a mute rule an operator creates", func() {
		accepted := api.MuteRule{
			Name:      "accepted-public-logs",
			Comment:   "logs bucket is public on purpose",
			Templates: api.StringList{check},
		}

		BeforeEach(func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(1, "logs", check)},
			})
			Expect(state("logs", check).Status).To(Equal(api.StatusOpen))
		})

		AfterEach(func() {
			Expect(db.Gorm().Exec(`DELETE FROM mute_rules`).Error).To(Succeed())
		})

		It("accepts what is already open, without waiting for another run", func() {
			_, err := st.CreateMute(ctx, accepted)
			Expect(err).ToNot(HaveOccurred())

			muted := state("logs", check)
			Expect(muted.Status).To(Equal(api.StatusMuted))
			Expect(*muted.MutedBy).To(Equal(accepted.Name),
				"the rule as a value, so deleting it can find exactly this row")
			Expect(*muted.Reason).To(Equal("mute:" + accepted.Name))
		})

		// A mute is a person's decision, not a run's observation. Stamping the
		// latest scan onto it would make the ledger claim that run said so.
		It("does not attribute the decision to a scan", func() {
			before := state("logs", check)
			_, err := st.CreateMute(ctx, accepted)
			Expect(err).ToNot(HaveOccurred())

			after := state("logs", check)
			Expect(after.LastScanID).To(Equal(before.LastScanID))
			Expect(after.LastSeen).To(BeTemporally("==", before.LastSeen))
		})

		It("reopens what it was suppressing when the rule is deleted", func() {
			_, err := st.CreateMute(ctx, accepted)
			Expect(err).ToNot(HaveOccurred())
			Expect(st.DeleteMute(ctx, accepted.Name)).To(Succeed())

			reopened := state("logs", check)
			Expect(reopened.Status).To(Equal(api.StatusOpen),
				"nobody accepts this any more, and the rule that said so is gone")
			Expect(reopened.MutedBy).To(BeNil())
			Expect(reopened.Reason).To(BeNil())
		})

		It("lets go of what it no longer covers when the rule is narrowed", func() {
			_, err := st.CreateMute(ctx, accepted)
			Expect(err).ToNot(HaveOccurred())
			Expect(state("logs", check).Status).To(Equal(api.StatusMuted))

			narrowed := accepted
			narrowed.Templates = api.StringList{another}
			_, err = st.UpdateMute(ctx, narrowed)
			Expect(err).ToNot(HaveOccurred())

			Expect(state("logs", check).Status).To(Equal(api.StatusOpen),
				"an edit has to release what it stopped selecting, not only take what it now does")
		})

		It("releases everything while it is disabled", func() {
			_, err := st.CreateMute(ctx, accepted)
			Expect(err).ToNot(HaveOccurred())

			suspended := accepted
			suspended.Disabled = true
			_, err = st.UpdateMute(ctx, suspended)
			Expect(err).ToNot(HaveOccurred())

			Expect(state("logs", check).Status).To(Equal(api.StatusOpen))
		})
	})

	// A finding whose subject the run did not emit.
	//
	// findings.resource_id is nullable and openFromFindingsSQL skips a NULL, so
	// the schema has always described this as a real state — but the write path
	// made it unreachable by aborting instead, and the abort took the whole
	// FinalizeScan transaction with it: the run's terminal phase, its output, its
	// resources and every other finding it wrote.
	Describe("a finding naming a resource the run did not emit", func() {
		stray := func(line int, uid string) api.Finding {
			finding := failure(line, uid, check)
			// The shape nuclei produces: resources come from the input file while
			// a finding's come from event.URL, so a dns template against an
			// `https://…/` line names a uid the run never emitted.
			finding.Resources = []api.ResourceRef{
				{Provider: provider, Scope: account, UID: "never-emitted", Name: "never-emitted"},
			}
			return finding
		}

		It("records the finding and keeps the rest of the run", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings: []api.Finding{
					failure(1, "logs", check),
					stray(2, "logs"),
				},
			})

			var rows []models.Finding
			Expect(db.Gorm().Raw(`SELECT * FROM findings ORDER BY line_no`).Scan(&rows).Error).To(Succeed())
			Expect(rows).To(HaveLen(2), "one bad record must not discard the run's evidence")
			Expect(rows[0].ResourceID).ToNot(BeNil())
			Expect(rows[1].ResourceID).To(BeNil(), "recorded without a subject, not dropped")

			// The run itself survived, which is the whole point.
			var phase string
			Expect(db.Gorm().Raw(`SELECT phase FROM scans`).Scan(&phase).Error).To(Succeed())
			Expect(phase).To(Equal(string(api.PhaseDone)))

			// Evidence with no lifecycle: the ledger keys on a resource, so there
			// is nothing for it to be a row about.
			Expect(states()).To(HaveLen(1))
		})

		It("does not fail the run when a mute rule matches one", func() {
			muted := stray(2, "logs")
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{failure(1, "logs", check)},
				muted:        []api.Finding{muted},
				mutedBy:      map[string][]int{"accepted-endpoints": {2}},
			})

			Expect(state("logs", check).Status).To(Equal(api.StatusOpen))
		})
	})

	// What a check is, as opposed to what it found.
	//
	// The description used to live only on the evidence: `findings` cascades away
	// with its scan and finding_states.finding_id goes NULL the moment a check
	// resolves, so what was left of a problem somebody still has to fix was an id
	// and a severity. Hydration papered over that by re-deriving the newest
	// finding for the pair, which meant a resolved state rendered the last time
	// it failed as though that were current.
	Describe("the check catalogue", func() {
		hydrated := func(uid, checkID string) api.Finding {
			GinkgoHelper()
			page, err := st.ListFindingStatesPaged(ctx, store.FindingStateOpts{Check: []string{checkID}})
			Expect(err).ToNot(HaveOccurred())
			for _, state := range page.Data {
				if state.Resource != nil && state.Resource.UID == uid {
					Expect(state.Finding).ToNot(BeNil())
					return *state.Finding
				}
			}
			Fail("no hydrated state for " + uid + "/" + checkID)
			return api.Finding{}
		}

		described := func(line int, uid, checkID string) api.Finding {
			finding := failure(line, uid, checkID)
			finding.Name = "Buckets must not be public"
			finding.Remediation = "Remove allUsers from the bucket IAM policy"
			finding.Reference = []string{"https://example.test/cis-5-1"}
			return finding
		}

		It("renders an open finding from its own evidence", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{described(1, "logs", check)},
			})

			evidence := hydrated("logs", check)
			Expect(evidence.Synthetic).To(BeFalse(), "an open state has evidence and must show it")
			Expect(evidence.ID).To(Equal(*state("logs", check).FindingID),
				"the finding the ledger names, not whichever one is newest")
			Expect(evidence.Remediation).To(Equal("Remove allUsers from the bucket IAM policy"))
		})

		It("still describes a check after the run that reported it is gone", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{described(1, "logs", check)},
			})
			// Retention, one day. The evidence cascades; the ledger must not, and
			// until the catalogue existed it could not render itself either.
			Expect(db.Gorm().Exec(`DELETE FROM scans`).Error).To(Succeed())

			var remaining int64
			Expect(db.Gorm().Raw(`SELECT count(*) FROM findings`).Scan(&remaining).Error).To(Succeed())
			Expect(remaining).To(BeZero(), "findings cascade away with their scan")

			orphan := state("logs", check)
			Expect(orphan.FindingID).To(BeNil())

			var described models.Check
			Expect(db.Gorm().Raw(`SELECT * FROM checks WHERE engine = ? AND check_id = ?`,
				"prowler", check).Scan(&described).Error).To(Succeed())
			Expect(described.Name).To(Equal("Buckets must not be public"))
			Expect(*described.Remediation).To(Equal("Remove allUsers from the bucket IAM policy"))
		})

		// The reason a state resolved is not advice on how to fix it. Stuffing
		// `resource-absent` into the remediation field made an invented document
		// indistinguishable from a real finding that recommended it.
		It("marks a description that is not evidence, and keeps the reason out of it", func() {
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs")},
				findings:     []api.Finding{described(1, "logs", check)},
			})
			scan(outcome{
				passRecorded: true,
				resources:    []api.Resource{resource("logs", check)},
			})

			fixed := state("logs", check)
			Expect(fixed.Status).To(Equal(api.StatusResolved))
			Expect(fixed.FindingID).To(BeNil())

			// The failing finding is still on disk. Rendering the check rather
			// than that row is the choice being asserted, not a consequence of
			// there being nothing else to show: hydration used to search for the
			// newest finding matching the pair and would find this one.
			var stale int64
			Expect(db.Gorm().Raw(`SELECT count(*) FROM findings WHERE template_id = ?`, check).
				Scan(&stale).Error).To(Succeed())
			Expect(stale).To(Equal(int64(1)))

			shown := hydrated("logs", check)
			Expect(shown.Synthetic).To(BeTrue())
			Expect(shown.Name).To(Equal("Buckets must not be public"),
				"the catalogue still knows what the check is")
			Expect(shown.Remediation).To(Equal("Remove allUsers from the bucket IAM policy"))
			Expect(shown.Remediation).ToNot(Equal(api.ReasonPassed))
		})
	})

	// One definition of what the ledger shows.
	//
	// The listings used to join `scans ON phase = 'done'` and the open-finding
	// counts on a resource row did not. Reconciliation stamps last_scan_id in
	// every terminal phase, so a run that died partway took every state it
	// touched out of the listing while leaving it in the badge above it.
	Describe("what a run that did not finish changes", func() {
		openStates := func() int {
			GinkgoHelper()
			page, err := st.ListFindingStatesPaged(ctx,
				store.FindingStateOpts{Status: []string{api.StatusOpen}})
			Expect(err).ToNot(HaveOccurred())
			return int(page.Page.Total)
		}

		failing := outcome{
			passRecorded: true,
			resources:    []api.Resource{resource("logs")},
			findings:     []api.Finding{failure(1, "logs", check)},
		}

		It("does not hide a finding an earlier successful run opened", func() {
			scan(failing)
			Expect(openStates()).To(Equal(1))

			died := failing
			died.phase = api.PhaseFailed
			scan(died)

			Expect(openStates()).To(Equal(1),
				"a run that dies partway adds nothing; it must not subtract")
		})

		It("counts the same open findings on the resource and in the listing", func() {
			scan(failing)
			died := failing
			died.phase = api.PhaseFailed
			scan(died)

			resources, err := st.ListResources(ctx, store.ResourceOpts{})
			Expect(err).ToNot(HaveOccurred())
			Expect(resources).To(HaveLen(1))
			Expect(resources[0].Findings).To(Equal(openStates()),
				"the badge and the list behind it answer the same question")
		})
	})
})
