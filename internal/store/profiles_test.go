package store_test

import (
	"context"
	"testing"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines/scan/nuclei"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("the built-in profile catalog", Ordered, Label("db"), func() {
	var (
		db  *dbtest.DB
		st  *store.Store
		ctx context.Context
	)

	BeforeAll(func() {
		if testing.Short() {
			Skip("needs a database")
		}
		db = dbtest.ForGinkgo(dbtest.Options{
			Name:        "recon_profiles",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
		DeferCleanup(func() {
			Expect(db.Gorm().Exec(`DELETE FROM engine_profiles`).Error).To(Succeed())
		})
	})

	It("seeds every Nuclei scan profile so manual runs can select any of them", func() {
		_, err := st.SeedDefaultProfiles(ctx)
		Expect(err).ToNot(HaveOccurred())

		profiles, err := st.ListProfiles(ctx, store.ProfileOpts{
			Kind:   []string{"scan"},
			Engine: []string{"nuclei"},
		})
		Expect(err).ToNot(HaveOccurred())

		// Compared against what the engine ships rather than a fixed list: the
		// imported community profiles come from the installed templates release,
		// so counting them here would make a template update a test failure.
		// What matters is that every profile the engine declares was stored.
		var seeded []string
		for _, profile := range profiles {
			seeded = append(seeded, profile.Name)
		}
		var declared []string
		for _, profile := range (nuclei.Engine{}).Spec().BuiltInProfiles() {
			declared = append(declared, profile.Name)
		}

		Expect(seeded).To(ConsistOf(declared))
	})

	It("does not overwrite an edited profile when seeding again", func() {
		// Seeding runs on every start. A profile someone tuned has to survive
		// it, or the edit lasts exactly until the next restart.
		_, err := st.SeedDefaultProfiles(ctx)
		Expect(err).ToNot(HaveOccurred())

		edited, err := st.GetProfile(ctx, "scan:nuclei:safe")
		Expect(err).ToNot(HaveOccurred())
		edited.Config["rate-limit"] = 5
		_, err = st.SaveProfile(ctx, edited)
		Expect(err).ToNot(HaveOccurred())

		_, err = st.SeedDefaultProfiles(ctx)
		Expect(err).ToNot(HaveOccurred())

		after, err := st.GetProfile(ctx, "scan:nuclei:safe")
		Expect(err).ToNot(HaveOccurred())
		Expect(after.Config["rate-limit"]).To(BeEquivalentTo(5))
	})
})
