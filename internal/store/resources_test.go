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
	"github.com/flanksource/recon/internal/ocsf"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

// The estate: one row per subject, however many checks reported it.
//
// A GCP report names the same resource once per check — 190 records for 94
// subjects — so the upsert runs far more often than it inserts, and every way
// it can go wrong is a way of losing information a previous check supplied.
var _ = Describe("the resource inventory", Ordered, Label("db"), func() {
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
			Name:        "recon_resources",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
	})

	BeforeEach(func() {
		Expect(db.Gorm().Exec(`DELETE FROM scans`).Error).To(Succeed())
		Expect(db.Gorm().Exec(`DELETE FROM resources`).Error).To(Succeed())
	})

	const account = "flanksource-prod"

	// record finalizes a run that examined the given resources, at a stated
	// time — because the upsert's ordering rules are the point of half of these
	// specs and a replay must be expressible.
	record := func(at time.Time, resources ...api.Resource) {
		GinkgoHelper()
		run++
		row, err := st.CreateScan(ctx, models.Scan{
			Name:   fmt.Sprintf("prowler-inventory-%d", run),
			Engine: "prowler", Profile: "gcp-cis-5-0",
			Phase: string(api.PhaseRunning), StartedAt: at,
		})
		Expect(err).ToNot(HaveOccurred())

		exitCode := 0
		row.Phase = string(api.PhaseDone)
		row.FinishedAt = &at
		row.ExitCode = &exitCode
		Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
			Scan: row, Resources: resources,
		})).To(Succeed())
	}

	bucket := api.Resource{
		Provider: "gcp", Scope: account, UID: "logs",
		Kind: api.KindCloudResource, Type: "storage.googleapis.com/Bucket",
		Name: "logs", Service: "storage", Region: "eu",
	}

	Describe("recording what a run examined", func() {
		It("keeps one row however many runs report the same subject", func() {
			first := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
			record(first, bucket)
			record(first.Add(time.Hour), bucket)

			listed, err := st.ListResources(ctx, store.ResourceOpts{})
			Expect(err).ToNot(HaveOccurred())
			Expect(listed).To(HaveLen(1))
			Expect(listed[0].UID).To(Equal("logs"))
		})

		// `default` is a VPC in every project. Keying on the uid alone would
		// merge two real resources into one row and attribute the second
		// project's findings to the first.
		It("keeps one row per account for a uid two accounts share", func() {
			elsewhere := bucket
			elsewhere.Scope = "workload-prod-eu-02"

			record(time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC), bucket, elsewhere)

			listed, err := st.ListResources(ctx, store.ResourceOpts{})
			Expect(err).ToNot(HaveOccurred())
			Expect(listed).To(HaveLen(2))
		})

		// The same resource arrives once per check, and most checks report only
		// the fields they care about. A later, thinner arrival must not blank
		// what an earlier one supplied — that is how a rich provider document
		// silently becomes an empty row partway through a scan.
		It("does not let a check that reported less blank what one reported more", func() {
			rich := bucket
			rich.Labels = map[string]string{"env": "prod"}
			rich.Metadata = map[string]any{"storageClass": "STANDARD"}
			rich.Tags = api.StringList{"cis"}

			thin := api.Resource{
				Provider: "gcp", Scope: account, UID: "logs",
				Kind: api.KindCloudResource,
			}

			at := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
			record(at, rich)
			record(at.Add(time.Hour), thin)

			kept, err := st.GetResource(ctx, "gcp/"+account+"/logs")
			Expect(err).ToNot(HaveOccurred())
			Expect(kept.Name).To(Equal("logs"))
			Expect(kept.Type).To(Equal("storage.googleapis.com/Bucket"))
			Expect(kept.Service).To(Equal("storage"))
			Expect(kept.Region).To(Equal("eu"))
			Expect(kept.Labels).To(HaveKeyWithValue("env", "prod"))
			Expect(kept.Metadata).To(HaveKeyWithValue("storageClass", "STANDARD"))
			Expect(kept.Tags).To(ConsistOf("cis"))
		})

		// first_seen is the age of the estate's knowledge of a thing. Replaying
		// an old artifact — which the retained results directories invite —
		// must not move it forward, and must not rewrite the newer document.
		It("does not let an older replay regress what a newer run recorded", func() {
			newer := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
			older := newer.Add(-48 * time.Hour)

			renamed := bucket
			renamed.Name = "logs-v2"

			record(newer, renamed)
			record(older, bucket)

			kept, err := st.GetResource(ctx, "gcp/"+account+"/logs")
			Expect(err).ToNot(HaveOccurred())
			Expect(kept.FirstSeen).To(ContainSubstring("2026-08-20"),
				"the earliest sighting, whichever order the runs were recorded in")
			Expect(kept.LastSeen).To(ContainSubstring("2026-08-22"),
				"and the latest, which the replay must not pull backwards")
		})

		It("refuses a resource that cannot be addressed", func() {
			row, err := st.CreateScan(ctx, models.Scan{
				Name: "prowler-invalid", Engine: "prowler", Profile: "p",
				Phase: string(api.PhaseRunning), StartedAt: time.Now(),
			})
			Expect(err).ToNot(HaveOccurred())
			at := time.Now()
			exitCode := 0
			row.Phase, row.FinishedAt, row.ExitCode = string(api.PhaseDone), &at, &exitCode

			// Loudly rather than skipped: a resource with no uid would collide
			// with every other uid-less resource on the unique key, and one of
			// them would become the run's only record of all of them.
			Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
				Scan:      row,
				Resources: []api.Resource{{Provider: "gcp", Scope: account}},
			})).To(MatchError(ContainSubstring("uid is required")))
		})

		// This used to abort the whole FinalizeScan transaction, which threw away
		// the run's terminal phase, its output, its resources and every other
		// finding on the strength of one record naming a subject the run did not
		// emit. resource_id is nullable and openFromFindingsSQL skips a NULL, so
		// the row is recorded without a subject instead: evidence with no
		// lifecycle, which is a lesser thing to be but a real one.
		It("records a finding whose canonical resource was not emitted, without its subject", func() {
			at := time.Now()
			row, err := st.CreateScan(ctx, models.Scan{
				Name: "prowler-unlinked", Engine: "prowler", Profile: "p",
				Phase: string(api.PhaseRunning), StartedAt: at,
			})
			Expect(err).ToNot(HaveOccurred())
			exitCode := 0
			row.Phase, row.FinishedAt, row.ExitCode = string(api.PhaseDone), &at, &exitCode

			finding := api.Finding{
				DetectionFinding: ocsf.DetectionFinding{
					FindingInfo: &ocsf.FindingInfo{
						UID: "gcp/bucket_public", Title: "Bucket is public",
					},
				},
				LineNo: 1, CheckID: "gcp/bucket_public", Engine: "prowler",
				Resources: []api.ResourceRef{{Provider: "gcp", Scope: "another-account", UID: "logs"}},
			}
			Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
				Scan: row, Resources: []api.Resource{bucket}, Findings: []api.Finding{finding},
			})).To(Succeed())

			var rows []models.Finding
			Expect(db.Gorm().Raw(`SELECT * FROM findings WHERE scan_id = ?`, row.ID).
				Scan(&rows).Error).To(Succeed())
			Expect(rows).To(HaveLen(1))
			Expect(rows[0].ResourceID).To(BeNil(),
				"the subject named is not one recon holds, and inventing a link would be worse")

			// The resource the run did emit is still recorded, which is what the
			// abort used to discard along with everything else.
			var resources int64
			Expect(db.Gorm().Raw(`SELECT count(*) FROM resources`).Scan(&resources).Error).To(Succeed())
			Expect(resources).To(Equal(int64(1)))
		})
	})

	Describe("addressing one resource", func() {
		BeforeEach(func() { record(time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC), bucket) })

		It("accepts the natural key a person would type", func() {
			found, err := st.GetResource(ctx, "gcp/"+account+"/logs")
			Expect(err).ToNot(HaveOccurred())
			Expect(found.Name).To(Equal("logs"))
		})

		It("accepts the id a row href carries", func() {
			listed, err := st.ListResources(ctx, store.ResourceOpts{})
			Expect(err).ToNot(HaveOccurred())

			found, err := st.GetResource(ctx, listed[0].ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(found.UID).To(Equal("logs"))
		})

		It("reports a missing resource rather than an empty one", func() {
			_, err := st.GetResource(ctx, "gcp/"+account+"/nothing")
			Expect(err).To(MatchError(ContainSubstring("not found")))
		})
	})

	Describe("narrowing the estate", func() {
		BeforeEach(func() {
			key := api.Resource{
				Provider: "gcp", Scope: "workload-prod-eu-02", UID: "prod-key",
				Kind: api.KindCloudResource, Type: "apikeys.googleapis.com/Key",
				Name: "prod-key", Service: "apikeys", Region: "global",
			}
			record(time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC), bucket, key)
		})

		DescribeTable("matches only what the filter names",
			func(opts store.ResourceOpts, expected ...string) {
				listed, err := st.ListResources(ctx, opts)
				Expect(err).ToNot(HaveOccurred())

				names := make([]string, 0, len(listed))
				for _, resource := range listed {
					names = append(names, resource.Name)
				}
				Expect(names).To(ConsistOf(expected))
			},
			Entry("by account", store.ResourceOpts{Account: []string{account}}, "logs"),
			Entry("by type", store.ResourceOpts{Type: []string{"storage.googleapis.com/Bucket"}}, "logs"),
			Entry("by service", store.ResourceOpts{Service: []string{"apikeys"}}, "prod-key"),
			Entry("by region", store.ResourceOpts{Region: []string{"eu"}}, "logs"),
			// The `!` grammar the UI's tri-state control sends. A server that
			// read it as a literal type name would match nothing and look like
			// a working exclusion.
			Entry("by an excluded type",
				store.ResourceOpts{Type: []string{"!storage.googleapis.com/Bucket"}}, "prod-key"),
			Entry("by substring", store.ResourceOpts{Search: "log"}, "logs"),
			Entry("by everything at once",
				store.ResourceOpts{Account: []string{account}, Service: []string{"storage"}}, "logs"),
		)

		It("rejects a state that is not one", func() {
			_, err := st.ListResources(ctx, store.ResourceOpts{State: []string{"deleted"}})
			Expect(err).To(MatchError(ContainSubstring(`unknown state "deleted"`)))
		})

		It("filters first and last sightings by inclusive date ranges", func() {
			later := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
			newResource := bucket
			newResource.UID, newResource.Name = "new-bucket", "new-bucket"
			record(later, bucket, newResource)

			firstSeen, err := st.ListResources(ctx, store.ResourceOpts{
				FirstSeen: ">=2026-08-24,<=2026-08-24",
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(firstSeen).To(HaveLen(1))
			Expect(firstSeen[0].Name).To(Equal("new-bucket"))

			lastSeen, err := st.ListResources(ctx, store.ResourceOpts{
				LastSeen: ">=2026-08-24,<=2026-08-24",
			})
			Expect(err).ToNot(HaveOccurred())
			Expect([]string{lastSeen[0].Name, lastSeen[1].Name}).To(ConsistOf("logs", "new-bucket"))
		})

		It("rejects an invalid sighting range", func() {
			_, err := st.ListResources(ctx, store.ResourceOpts{FirstSeen: "2026-08-24"})
			Expect(err).To(MatchError(ContainSubstring("first-seen range")))
		})

		// The envelope exists so "what have I got" has a true answer. A page
		// whose total is the page size is not a partial answer, it is a wrong
		// one — so the count has to ignore the limit.
		It("reports the whole total alongside one page", func() {
			page, err := st.ListResourcesPaged(ctx, store.ResourceOpts{Limit: 1})
			Expect(err).ToNot(HaveOccurred())

			Expect(page.Data).To(HaveLen(1))
			Expect(page.Page.Total).To(Equal(int64(2)))
			Expect(page.Page.Limit).To(Equal(1))
		})

		It("counts the whole filtered set, not the whole table", func() {
			page, err := st.ListResourcesPaged(ctx,
				store.ResourceOpts{Account: []string{account}, Limit: 10})
			Expect(err).ToNot(HaveOccurred())
			Expect(page.Page.Total).To(Equal(int64(1)))
		})
	})

	// The read side: what is open against each resource, counted at read time
	// because a mute-rule edit changes the answer without touching the resource.
	Describe("what is open against a resource", func() {
		It("carries per-severity counts for the rows on the page", func() {
			at := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
			run++
			row, err := st.CreateScan(ctx, models.Scan{
				Name: "prowler-counts", Engine: "prowler", Profile: "p",
				Phase: string(api.PhaseRunning), StartedAt: at,
			})
			Expect(err).ToNot(HaveOccurred())
			exitCode := 0
			row.Phase, row.FinishedAt, row.ExitCode = string(api.PhaseDone), &at, &exitCode

			finding := func(line int, severity api.Severity, check string) api.Finding {
				return api.Finding{
					DetectionFinding: ocsf.DetectionFinding{
						SeverityID:  api.SeverityID(severity),
						FindingInfo: &ocsf.FindingInfo{UID: check, Title: check},
					},
					LineNo: line, CheckID: check, Engine: "prowler",
					Host: account, MatchedAt: "logs",
					Resources: []api.ResourceRef{{Provider: "gcp", Scope: account, UID: "logs", Name: "logs"}},
				}
			}
			manual := finding(4, api.SeverityMedium, "gcp/manual-review")
			// The engine's own status code is an OCSF field of its own now; the
			// lifecycle keys on recon's vocabulary instead, so that a matcher an
			// engine happens to name MANUAL cannot mint manual states.
			manual.StatusCode = "MANUAL"
			manual.Verdict = api.VerdictManual
			manual.FindingInfo = &ocsf.FindingInfo{
				UID: "gcp/manual-review", Title: "Manual approval required",
			}
			clean := bucket
			clean.UID, clean.Name = "scratch", "scratch"
			Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
				Scan: row, Resources: []api.Resource{bucket, clean},
				Findings: []api.Finding{
					finding(1, api.SeverityHigh, "gcp/public"),
					finding(2, api.SeverityHigh, "gcp/versioning"),
					finding(3, api.SeverityLow, "gcp/labels"),
					manual,
				},
			})).To(Succeed())

			found, err := st.GetResource(ctx, "gcp/"+account+"/logs")
			Expect(err).ToNot(HaveOccurred())
			Expect(found.Findings).To(Equal(4))
			Expect(found.Severities).To(Equal(map[string]int{"high": 2, "medium": 1, "low": 1}))

			states, err := st.ListFindingStatesPaged(ctx, store.FindingStateOpts{
				Check: []string{"gcp/manual-review"}, Status: []string{api.StatusOpen}, Limit: 10,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(states.Data).To(HaveLen(1))
			Expect(states.Data[0].Status).To(Equal(api.StatusManual))
			Expect(states.Data[0].Finding.FindingInfo.Title).To(Equal("Manual approval required"))
			Expect([]string{
				states.Data[0].Resource.Provider,
				states.Data[0].Resource.Scope,
				states.Data[0].Resource.UID,
				states.Data[0].Resource.Type,
			}).To(Equal([]string{"gcp", account, "logs", "storage.googleapis.com/Bucket"}))

			groups, err := st.ListFindingGroupsPaged(ctx, store.FindingStateOpts{
				Check: []string{"gcp/manual-review"}, Status: []string{api.StatusOpen}, Limit: 10,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(groups.Data).To(HaveLen(1))
			Expect(groups.Data[0].Name).To(Equal("Manual approval required"))

			withResolved, err := st.ListFindingStatesPaged(ctx, store.FindingStateOpts{
				Check:  []string{"gcp/manual-review"},
				Status: []string{api.StatusOpen, api.StatusResolved},
				Limit:  10,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(withResolved.Data).To(HaveLen(1), "adding resolved must retain manual-review states")

			page, err := st.ListResourcesPaged(ctx, store.ResourceOpts{
				Sort: "worst", Order: "asc", Limit: 10,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(page.Data).To(HaveLen(2))
			Expect([]string{page.Data[0].Name, page.Data[1].Name}).To(Equal([]string{"logs", "scratch"}))
		})

		// The three-way distinction recording passing checks creates. Without
		// passes, `clean` and `unchecked` are the same row and the filter is a
		// lie.
		DescribeTable("tells a clean resource from one nobody checked",
			func(status string, expected ...string) {
				at := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
				checked := bucket
				checked.Passed = api.StringList{"gcp/public"}
				unchecked := api.Resource{
					Provider: "gcp", Scope: account, UID: "scratch",
					Kind: api.KindCloudResource, Name: "scratch",
					Type: "storage.googleapis.com/Bucket",
				}
				record(at, checked, unchecked)

				listed, err := st.ListResources(ctx, store.ResourceOpts{Status: []string{status}})
				Expect(err).ToNot(HaveOccurred())

				names := make([]string, 0, len(listed))
				for _, resource := range listed {
					names = append(names, resource.Name)
				}
				Expect(names).To(ConsistOf(expected))
			},
			Entry("clean: a check ran and passed", store.ResourceClean, "logs"),
			Entry("unchecked: nothing has reported a verdict", store.ResourceUnchecked, "scratch"),
			Entry("failing: nothing is", store.ResourceFailing),
		)
	})

	// Which Mission Control config item a resource's insights hang off, once
	// somebody has answered that question for an identity the catalog gave more
	// than one answer to.
	Describe("the config item chosen for a resource", func() {
		const chosen = "3f2a1c4e-0000-4000-8000-00000000000d"

		It("survives the runs that keep re-reporting the resource", func() {
			at := time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC)
			record(at, bucket)
			stored, err := st.GetResource(ctx, "gcp/"+account+"/logs")
			Expect(err).ToNot(HaveOccurred())

			Expect(st.SetConfigPins(ctx, map[string]api.ConfigPin{
				stored.ID: {ConfigID: chosen, RolledUp: true},
			})).To(Succeed())
			record(at.Add(time.Hour), bucket)

			Expect(st.ConfigPins(ctx, []string{stored.ID})).To(Equal(map[string]api.ConfigPin{
				stored.ID: {ConfigID: chosen, Method: api.ConfigMatchManual, RolledUp: true},
			}))
			reread, err := st.GetResource(ctx, stored.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(reread.ConfigID).To(Equal(chosen))
		})

		// Absent rather than zero: a sync has to tell "attach here" from "nobody
		// has decided", and a zero uuid would resolve to a config item that does
		// not exist.
		It("reports nothing for a resource nobody has chosen for", func() {
			record(time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC), bucket)
			stored, err := st.GetResource(ctx, "gcp/"+account+"/logs")
			Expect(err).ToNot(HaveOccurred())

			Expect(st.ConfigPins(ctx, []string{stored.ID})).To(BeEmpty())
			Expect(stored.ConfigID).To(BeEmpty())
		})

		It("removes the chosen config item without removing the resource", func() {
			record(time.Date(2026, 8, 22, 9, 0, 0, 0, time.UTC), bucket)
			stored, err := st.GetResource(ctx, "gcp/"+account+"/logs")
			Expect(err).ToNot(HaveOccurred())
			Expect(st.SetConfigPins(ctx, map[string]api.ConfigPin{
				stored.ID: {ConfigID: chosen, RolledUp: true},
			})).To(Succeed())

			removed, err := st.ClearConfigPin(ctx, stored.ID)

			Expect(err).ToNot(HaveOccurred())
			Expect(removed).To(Equal(chosen))
			Expect(st.ConfigPins(ctx, []string{stored.ID})).To(BeEmpty())
			kept, err := st.GetResource(ctx, stored.ID)
			Expect(err).ToNot(HaveOccurred())
			Expect(kept.ConfigID).To(BeEmpty())
		})
	})
})
