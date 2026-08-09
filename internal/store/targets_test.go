package store_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
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

		BeforeEach(func() {
			original = api.TargetDocument{
				Host: "a.example.test", Class: api.ClassNonProd,
				Profiles: []string{"safe"}, Tags: []string{"web"},
				App: "demo",
				// A machine-owned snapshot that must survive every edit.
				Observed: &api.Observed{FirstObserved: "2026-01-01T00:00:00Z", LastSeen: "2026-01-02T00:00:00Z"},
				HTTP:     &api.HTTP{URL: "https://a.example.test", StatusCode: 200},
				Scan:     &api.ScanState{LastScan: "2026-01-03T00:00:00Z"},
			}
			Expect(st.SaveTarget(ctx, original)).To(Succeed())
		})

		It("preserves machine-owned sections across a curated edit", func() {
			updated, err := st.UpdateCurated(ctx, "a.example.test", api.Curated{
				Class: api.ClassProd, Profiles: []string{"safe", "full"},
				Tags: []string{"web", "critical"}, App: "renamed",
			})
			Expect(err).ToNot(HaveOccurred())

			Expect(updated.Class).To(Equal(api.ClassProd))
			Expect(updated.App).To(Equal("renamed"))
			Expect(updated.Observed).To(Equal(original.Observed))
			Expect(updated.HTTP).To(Equal(original.HTTP))
			Expect(updated.Scan).To(Equal(original.Scan))
		})

		It("clears a curated field that is omitted", func() {
			updated, err := st.UpdateCurated(ctx, "a.example.test", api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"safe"}, Tags: []string{},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(updated.App).To(BeEmpty())
			Expect(updated.Tags).To(BeEmpty())
		})

		It("rejects a deactivation without a reason", func() {
			_, err := st.UpdateCurated(ctx, "a.example.test", api.Curated{
				Class: api.ClassDeactivated, Profiles: []string{"safe"}, Tags: []string{},
			})
			Expect(err).To(MatchError(ContainSubstring("reason")))
		})

		It("accepts a deactivation with a reason, and clears it on reactivation", func() {
			deactivated, err := st.UpdateCurated(ctx, "a.example.test", api.Curated{
				Class: api.ClassDeactivated, Profiles: []string{"safe"}, Tags: []string{},
				Reason: "retired",
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(deactivated.Reason).To(Equal("retired"))

			reactivated, err := st.UpdateCurated(ctx, "a.example.test", api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"safe"}, Tags: []string{},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(reactivated.Reason).To(BeEmpty())
		})

		It("rejects an unknown profile before it reaches the database", func() {
			_, err := st.UpdateCurated(ctx, "a.example.test", api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"aggressive"}, Tags: []string{},
			})
			Expect(err).To(MatchError(ContainSubstring("value must be one of")))
		})

		It("reports a missing target", func() {
			_, err := st.UpdateCurated(ctx, "nope.example.test", api.Curated{
				Class: api.ClassNonProd, Profiles: []string{"safe"}, Tags: []string{},
			})
			Expect(err).To(MatchError("target not found: nope.example.test"))
		})
	})

	Describe("the inventory listing", func() {
		It("sorts hosts by byte order and collects the tag vocabulary", func() {
			for _, document := range []api.TargetDocument{
				{Host: "b.example.test", Class: api.ClassNonProd, Profiles: []string{"safe"}, Tags: []string{"web", "beta"}},
				{Host: "a.example.test", Class: api.ClassProd, Profiles: []string{"safe"}, Tags: []string{"web"}},
				{Host: "c.example.test", Class: api.ClassPublic, Profiles: []string{"safe"}, Tags: []string{}},
			} {
				Expect(st.SaveTarget(ctx, document)).To(Succeed())
			}
			Expect(st.ReplaceZones(ctx, []string{"z.example.test", "a.example.test"})).To(Succeed())

			inventory, err := st.Inventory(ctx)
			Expect(err).ToNot(HaveOccurred())

			Expect(inventory.Version).To(Equal(1))
			Expect(hostsOf(inventory.Rows)).To(Equal([]string{"a.example.test", "b.example.test", "c.example.test"}))
			Expect(inventory.Zones).To(Equal([]string{"a.example.test", "z.example.test"}))
			Expect(inventory.TagVocabulary).To(Equal([]string{"beta", "web"}))
		})

		It("serialises an empty inventory with arrays rather than nulls", func() {
			inventory, err := st.Inventory(ctx)
			Expect(err).ToNot(HaveOccurred())

			encoded, err := json.Marshal(inventory)
			Expect(err).ToNot(HaveOccurred())
			Expect(encoded).To(MatchJSON(`{"version":1,"zones":[],"rows":[],"tagVocabulary":[]}`))
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
