package store_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "store")
}

func repoRoot() string {
	dir, err := os.Getwd()
	Expect(err).ToNot(HaveOccurred())
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		Expect(parent).ToNot(Equal(dir), "go.mod not found above the working directory")
		dir = parent
	}
}

func loadDocuments(pattern string) []api.TargetDocument {
	paths, err := filepath.Glob(filepath.Join(repoRoot(), pattern))
	Expect(err).ToNot(HaveOccurred())

	documents := make([]api.TargetDocument, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		Expect(err).ToNot(HaveOccurred())
		var document api.TargetDocument
		Expect(json.Unmarshal(raw, &document)).To(Succeed(), path)
		if document.Version < api.TargetVersion {
			document.ID = document.Host
			for i, profile := range document.Profiles {
				document.Profiles[i] = "scan:nuclei:" + profile
			}
		}
		documents = append(documents, document)
	}
	return documents
}

var _ = Describe("the target store", Ordered, Label("db"), func() {
	var (
		db  *dbtest.DB
		st  *store.Store
		ctx context.Context
	)

	BeforeAll(func() {
		// -short is the suite that needs no database, so that a checkout can be
		// verified without provisioning Postgres.
		if testing.Short() {
			Skip("needs a database")
		}
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_store",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
	})

	AfterEach(func() {
		Expect(db.Gorm().Exec(`DELETE FROM targets`).Error).To(Succeed())
		Expect(db.Gorm().Exec(`DELETE FROM zones`).Error).To(Succeed())
	})

	// The wire round-trip already proved the Go types are lossless. This proves
	// the same for a full trip through Postgres, where the jsonb encoding and the
	// text[]/integer[] conversions are the parts that can quietly drop data.
	//
	// The committed snapshot is the floor; the gitignored full capture is the
	// stronger version and runs whenever a developer still has it locally.
	It("round-trips every captured document through the database", func() {
		documents := loadDocuments("contract/snapshot/inventory/targets/*.json")
		Expect(documents).ToNot(BeEmpty())
		documents = append(documents, loadDocuments("contract/golden/full/targets/*.json")...)

		for _, document := range documents {
			Expect(st.SaveTarget(ctx, document)).To(Succeed(), document.Host)
		}

		for _, document := range documents {
			stored, err := st.GetTarget(ctx, document.Host)
			Expect(err).ToNot(HaveOccurred())

			expected, err := json.Marshal(document)
			Expect(err).ToNot(HaveOccurred())
			actual, err := json.Marshal(stored)
			Expect(err).ToNot(HaveOccurred())
			Expect(actual).To(MatchJSON(expected), "target %s", document.Host)
		}
	})

	It("reports a missing target with the message the UI renders", func() {
		_, err := st.GetTarget(ctx, "nope.example.test")
		Expect(err).To(MatchError("target not found: nope.example.test"))
		Expect(store.IsNotFound(err)).To(BeTrue())
	})

	Describe("updating", func() {
		var original api.TargetDocument

		BeforeAll(func() {
			// A curated edit names a profile that has to exist, so the catalog the
			// server seeds on startup has to be here too.
			_, err := st.SeedDefaultProfiles(context.Background())
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(func() {
				Expect(db.Gorm().Exec(`DELETE FROM engine_profiles`).Error).To(Succeed())
			})
		})

		BeforeEach(func() {
			original = api.TargetDocument{
				Host: "a.example.test", Class: api.ClassNonProd,
				Profiles: []string{"scan:nuclei:safe"}, Tags: []string{"web"},
				App: "demo",
				// A machine-owned snapshot that must survive every edit.
				Observed: &api.Observed{FirstObserved: "2026-01-01T00:00:00Z", LastSeen: "2026-01-02T00:00:00Z"},
				HTTP:     &api.HTTP{URL: "https://a.example.test", StatusCode: 200},
				Scan:     &api.ScanState{LastScan: "2026-01-03T00:00:00Z"},
			}
			Expect(st.SaveTarget(ctx, original)).To(Succeed())
		})

		It("preserves machine-owned sections across a curated edit", func() {
			updated, err := st.UpdateTarget(ctx, "a.example.test", api.TargetUpdate{Curated: api.Curated{
				Class: api.ClassProd, Profiles: []string{"scan:nuclei:safe", "scan:nuclei:full"},
				Tags: []string{"web", "critical"}, App: "renamed",
			}})
			Expect(err).ToNot(HaveOccurred())

			Expect(updated.Class).To(Equal(api.ClassProd))
			Expect(updated.App).To(Equal("renamed"))
			Expect(updated.Observed).To(Equal(original.Observed))
			Expect(updated.HTTP).To(Equal(original.HTTP))
			Expect(updated.Scan).To(Equal(original.Scan))
		})

		It("clears a curated field that is omitted", func() {
			updated, err := st.UpdateTarget(ctx, "a.example.test", api.TargetUpdate{Curated: api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
			}})
			Expect(err).ToNot(HaveOccurred())
			Expect(updated.App).To(BeEmpty())
			Expect(updated.Tags).To(BeEmpty())
		})

		It("rejects a deactivation without a reason", func() {
			_, err := st.UpdateTarget(ctx, "a.example.test", api.TargetUpdate{Curated: api.Curated{
				Class: api.ClassDeactivated, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
			}})
			Expect(err).To(MatchError(ContainSubstring("reason")))
		})

		It("accepts a deactivation with a reason, and clears it on reactivation", func() {
			deactivated, err := st.UpdateTarget(ctx, "a.example.test", api.TargetUpdate{Curated: api.Curated{
				Class: api.ClassDeactivated, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
				Reason: "retired",
			}})
			Expect(err).ToNot(HaveOccurred())
			Expect(deactivated.Reason).To(Equal("retired"))

			reactivated, err := st.UpdateTarget(ctx, "a.example.test", api.TargetUpdate{Curated: api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
			}})
			Expect(err).ToNot(HaveOccurred())
			Expect(reactivated.Reason).To(BeEmpty())
		})

		// Profile names are rows, not a closed vocabulary, so the schema can only
		// check the shape of one. Existence is checked against the catalog: a
		// typo here means a host is quietly never scanned by what was intended.
		It("rejects a profile name nobody defined, naming what is available", func() {
			_, err := st.UpdateTarget(ctx, "a.example.test", api.TargetUpdate{Curated: api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"scan:nuclei:aggressive"}, Tags: []string{},
			}})
			Expect(err).To(MatchError(ContainSubstring("unknown scan profile scan:nuclei:aggressive")))
			Expect(err).To(MatchError(ContainSubstring("safe")))
		})

		It("accepts a focused profile the engine ships", func() {
			updated, err := st.UpdateTarget(ctx, "a.example.test", api.TargetUpdate{Curated: api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"scan:nuclei:k8s", "scan:nuclei:static"}, Tags: []string{},
			}})
			Expect(err).ToNot(HaveOccurred())
			Expect(updated.Profiles).To(Equal([]string{"scan:nuclei:k8s", "scan:nuclei:static"}))
		})

		It("reports a missing target", func() {
			_, err := st.UpdateTarget(ctx, "nope.example.test", api.TargetUpdate{Curated: api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
			}})
			Expect(err).To(MatchError("target not found: nope.example.test"))
		})
	})

	Describe("auto-inventory from discovery", func() {
		It("creates a safe unclassified target", func() {
			created, err := st.EnsureDiscoveredTarget(ctx, "192.0.2.10")
			Expect(err).ToNot(HaveOccurred())
			Expect(created.Curated()).To(Equal(api.Curated{
				Class: api.ClassUnclassified, Source: "discovery",
				Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
			}))
		})

		It("preserves an existing target's curated fields", func() {
			original := api.TargetDocument{
				Host: "curated.example.test", Class: api.ClassProd, Source: "inventory",
				Profiles: []string{"scan:nuclei:full"}, Tags: []string{"critical"},
			}
			Expect(st.SaveTarget(ctx, original)).To(Succeed())

			stored, err := st.EnsureDiscoveredTarget(ctx, original.Host)
			Expect(err).ToNot(HaveOccurred())
			Expect(stored.Curated()).To(Equal(original.Curated()))
		})
	})

	Describe("the inventory listing", func() {
		It("sorts hosts by byte order and collects the tag vocabulary", func() {
			for _, document := range []api.TargetDocument{
				{Host: "b.example.test", Class: api.ClassNonProd, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{"web", "beta"}},
				{Host: "a.example.test", Class: api.ClassProd, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{"web"}},
				{Host: "c.example.test", Class: api.ClassPublic, Profiles: []string{"scan:nuclei:safe"}, Tags: []string{}},
			} {
				Expect(st.SaveTarget(ctx, document)).To(Succeed())
			}
			Expect(st.ReplaceZones(ctx, []string{"z.example.test", "a.example.test"})).To(Succeed())

			inventory, err := st.Inventory(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(inventory.Version).To(Equal(api.TargetVersion))
			Expect(hostsOf(inventory.Rows)).To(Equal([]string{"a.example.test", "b.example.test", "c.example.test"}))
			Expect(inventory.Zones).To(Equal([]string{"a.example.test", "z.example.test"}))
			Expect(inventory.TagVocabulary).To(Equal([]string{"beta", "web"}))
		})

		It("serialises an empty inventory with arrays rather than nulls", func() {
			inventory, err := st.Inventory(ctx)
			Expect(err).ToNot(HaveOccurred())

			encoded, err := json.Marshal(inventory)
			Expect(err).ToNot(HaveOccurred())
			Expect(encoded).To(MatchJSON(`{"version":3,"zones":[],"rows":[],"tagVocabulary":[]}`))
		})
	})

	Describe("importing", func() {
		const host = "imported.example.test"

		definition := func(build ...func(*api.Curated)) api.NewTarget {
			curated := api.Curated{
				Class: api.ClassNonProd, Source: "inventory",
				Profiles: api.StringList{"scan:nuclei:safe"}, Tags: api.StringList{"web"},
			}
			for _, apply := range build {
				apply(&curated)
			}
			return api.NewTarget{Host: host, Kind: api.KindHost, Curated: curated}
		}

		BeforeAll(func() {
			// An import validates the profiles it writes, so the catalog the
			// server seeds on startup has to be here too.
			_, err := st.SeedDefaultProfiles(context.Background())
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(func() {
				Expect(db.Gorm().Exec(`DELETE FROM engine_profiles`).Error).To(Succeed())
			})
		})

		It("creates a target that was not in the inventory", func() {
			result, err := st.ImportTargets(ctx, []api.NewTarget{definition()})

			Expect(err).ToNot(HaveOccurred())
			Expect(result.Created).To(Equal([]string{host}))
			Expect(result.Updated).To(BeEmpty())

			stored, err := st.GetTarget(ctx, host)
			Expect(err).ToNot(HaveOccurred())
			Expect(stored.Class).To(Equal(api.ClassNonProd))
		})

		It("reports the second run as unchanged rather than as an update", func() {
			// Re-importing is how the inventory files stay authoritative, so it
			// has to be a visible no-op — otherwise every run reads as a change
			// and nobody can tell a real edit from a repeat.
			_, err := st.ImportTargets(ctx, []api.NewTarget{definition()})
			Expect(err).ToNot(HaveOccurred())

			result, err := st.ImportTargets(ctx, []api.NewTarget{definition()})

			Expect(err).ToNot(HaveOccurred())
			Expect(result.Unchanged).To(Equal([]string{host}))
			Expect(result.Created).To(BeEmpty())
			Expect(result.Updated).To(BeEmpty())
		})

		It("applies a changed curated field to a target that already exists", func() {
			_, err := st.ImportTargets(ctx, []api.NewTarget{definition()})
			Expect(err).ToNot(HaveOccurred())

			result, err := st.ImportTargets(ctx, []api.NewTarget{
				definition(func(c *api.Curated) { c.Class = api.ClassInternal }),
			})

			Expect(err).ToNot(HaveOccurred())
			Expect(result.Updated).To(Equal([]string{host}))

			stored, err := st.GetTarget(ctx, host)
			Expect(err).ToNot(HaveOccurred())
			Expect(stored.Class).To(Equal(api.ClassInternal))
		})

		It("leaves an observation alone, so a re-import does not undo a sweep", func() {
			// The import carries no observed section — it never does — and the
			// point is that this means "unchanged", not "cleared".
			Expect(st.SaveTarget(ctx, api.TargetDocument{
				Host: host, Class: api.ClassNonProd, Source: "inventory",
				Profiles: []string{"scan:nuclei:safe"}, Tags: []string{"web"},
				Observed: &api.Observed{LastSeen: "2026-08-10T00:00:00Z"},
			})).To(Succeed())

			result, err := st.ImportTargets(ctx, []api.NewTarget{definition()})
			Expect(err).ToNot(HaveOccurred())
			Expect(result.Unchanged).To(Equal([]string{host}))

			stored, err := st.GetTarget(ctx, host)
			Expect(err).ToNot(HaveOccurred())
			Expect(stored.Observed.LastSeen).To(Equal("2026-08-10T00:00:00Z"))
		})

		It("refuses to change what kind of thing a target is", func() {
			// Kind decides how every future run reaches it, so an import that
			// disagrees is a mistake to report rather than a change to make.
			Expect(st.SaveTarget(ctx, api.TargetDocument{
				ID: "gcp-imported", Kind: api.KindProviderContext, Provider: "gcp",
				CredentialMode: api.CredentialAmbient,
				Arguments:      map[string]any{"project-ids": []any{"acme-platform-imported"}},
				Class:          api.ClassProd, Profiles: []string{"scan:prowler:gcp-cis"}, Tags: []string{},
			})).To(Succeed())

			_, err := st.ImportTargets(ctx, []api.NewTarget{{
				ID: "gcp-imported", Host: "acme-platform-imported", Kind: api.KindHost,
				Curated: api.Curated{
					Class: api.ClassProd, Profiles: api.StringList{"scan:nuclei:safe"}, Tags: api.StringList{},
				},
			}})

			Expect(err).To(MatchError(ContainSubstring("already a provider-context and cannot become a host")))
		})

		It("refuses a profile nobody defined", func() {
			// Every curated write path checks this: a row naming a profile that
			// does not exist is never scanned, and rejecting it only on the next
			// edit would report the mistake too late.
			_, err := st.ImportTargets(ctx, []api.NewTarget{
				definition(func(c *api.Curated) { c.Profiles = api.StringList{"scan:nuclei:nonexistent"} }),
			})

			Expect(err).To(MatchError(ContainSubstring("unknown scan profile scan:nuclei:nonexistent")))
		})

		It("writes nothing at all when one document in the batch is bad", func() {
			// A partial import is the worst outcome: the inventory is neither
			// what it was nor what the files say, and nothing records which.
			_, err := st.ImportTargets(ctx, []api.NewTarget{
				definition(),
				{Host: "second.example.test", Kind: api.KindHost, Curated: api.Curated{
					Class: api.ClassNonProd, Profiles: api.StringList{"scan:nuclei:nonexistent"},
					Tags: api.StringList{},
				}},
			})

			Expect(err).To(HaveOccurred())

			_, err = st.GetTarget(ctx, host)
			Expect(store.IsNotFound(err)).To(BeTrue(),
				"the good document must have been rolled back with the bad one")
		})
	})

	Describe("deleting", func() {
		const host = "gone.example.test"

		BeforeEach(func() {
			Expect(st.SaveTarget(ctx, api.TargetDocument{
				Host: host, Class: api.ClassNonProd,
				Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
			})).To(Succeed())
		})

		It("removes the target from the inventory", func() {
			Expect(st.DeleteTarget(ctx, host)).To(Succeed())

			_, err := st.GetTarget(ctx, host)
			Expect(store.IsNotFound(err)).To(BeTrue())
		})

		It("reports a target that is not there rather than succeeding quietly", func() {
			// A delete that reports success for a host it never had would make a
			// typo indistinguishable from the thing it was meant to remove.
			err := st.DeleteTarget(ctx, "never.example.test")

			Expect(err).To(MatchError("target not found: never.example.test"))
			Expect(store.IsNotFound(err)).To(BeTrue())
		})

		It("leaves what a scan already found behind", func() {
			// Nothing points a foreign key at targets, and that is deliberate:
			// removing a host from the inventory says nothing about whether the
			// finding was real when it was recorded.
			started := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
			selector := map[string]any{"hosts": []string{host}}
			run, err := st.CreateScan(ctx, models.Scan{
				Name: "nuclei-safe-20260810-120000", Engine: "nuclei", Profile: "safe",
				Selector: models.Wrap(&selector), EndpointCount: 1,
				Phase: string(api.PhaseRunning), StartedAt: started,
			})
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(func() {
				Expect(db.Gorm().Exec(`DELETE FROM scans`).Error).To(Succeed())
			})

			finished := started.Add(time.Second)
			exitCode := 0
			run.Phase, run.FinishedAt, run.ExitCode = string(api.PhaseDone), &finished, &exitCode
			endpoint := nucleiEndpointResource(host)
			Expect(st.FinalizeScan(ctx, store.FinalizeScanOptions{
				Scan:      run,
				Resources: []api.Resource{endpoint},
				Findings: []api.Finding{{
					DetectionFinding: detection("tls-version", "Deprecated TLS version", api.SeverityHigh),
					LineNo:           1,
					CheckID:          "tls-version",
					Engine:           "nuclei",
					Host:             host,
					Resources:        []api.ResourceRef{endpoint.Ref()},
				}},
			})).To(Succeed())

			Expect(st.DeleteTarget(ctx, host)).To(Succeed())

			findings, err := st.ListFindings(ctx, store.FindingOpts{Scan: []string{run.ID}})
			Expect(err).ToNot(HaveOccurred())
			Expect(findings).To(HaveLen(1))
			Expect(findings[0].Host).To(Equal(host))
		})
	})
})

func hostsOf(documents []api.TargetDocument) []string {
	hosts := make([]string, 0, len(documents))
	for _, document := range documents {
		hosts = append(hosts, document.Host)
	}
	return hosts
}
