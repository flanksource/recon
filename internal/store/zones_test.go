package store_test

import (
	"context"
	"testing"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("the configured zones", Ordered, Label("db"), func() {
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
			Name:        "recon_zones",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
	})

	AfterEach(func() {
		Expect(db.Gorm().Exec(`DELETE FROM zones`).Error).To(Succeed())
		Expect(db.Gorm().Exec(`DELETE FROM targets`).Error).To(Succeed())
	})

	names := func() []string {
		zones, err := st.ListZoneDocuments(ctx, store.ZoneOpts{})
		Expect(err).ToNot(HaveOccurred())
		var found []string
		for _, zone := range zones {
			found = append(found, zone.Zone)
		}
		return found
	}

	It("keeps zones in byte order so a sweep is reproducible", func() {
		for _, zone := range []string{"b.test", "a.test", "c.test"} {
			_, err := st.AddZone(ctx, zone)
			Expect(err).ToNot(HaveOccurred())
		}
		Expect(names()).To(Equal([]string{"a.test", "b.test", "c.test"}))
	})

	It("normalises what it is given", func() {
		zone, err := st.AddZone(ctx, "  Example.Test.  ")
		Expect(err).ToNot(HaveOccurred())
		Expect(zone.Zone).To(Equal("example.test"))
		Expect(names()).To(Equal([]string{"example.test"}))
	})

	It("treats adding the same zone twice as a no-op", func() {
		_, err := st.AddZone(ctx, "example.test")
		Expect(err).ToNot(HaveOccurred())
		_, err = st.AddZone(ctx, "EXAMPLE.TEST")
		Expect(err).ToNot(HaveOccurred())
		Expect(names()).To(HaveLen(1))
	})

	It("rejects something that is not a domain name", func() {
		_, err := st.AddZone(ctx, "localhost")
		Expect(err).To(MatchError(ContainSubstring("is not a domain name")))

		_, err = st.AddZone(ctx, "*.example.test")
		Expect(err).To(MatchError(ContainSubstring("characters a domain name cannot")))

		_, err = st.AddZone(ctx, "")
		Expect(err).To(MatchError(ContainSubstring("zone is required")))
	})

	It("reports a missing zone rather than succeeding silently", func() {
		Expect(st.DeleteZone(ctx, "absent.test")).To(MatchError("zone not found: absent.test"))

		_, err := st.GetZone(ctx, "absent.test")
		Expect(store.IsNotFound(err)).To(BeTrue())
	})

	It("leaves discovered targets alone when a zone is removed", func() {
		// The hosts are still real. Removing them with the zone would quietly
		// shrink the inventory, which is the opposite of what this tool is for.
		Expect(st.SaveTarget(ctx, api.TargetDocument{
			Schema: api.TargetSchemaRef, Version: api.TargetVersion,
			Host: "app.example.test", Class: api.ClassProd,
			Profiles: []string{"safe"}, Tags: []string{},
		})).To(Succeed())

		_, err := st.AddZone(ctx, "example.test")
		Expect(err).ToNot(HaveOccurred())
		Expect(st.DeleteZone(ctx, "example.test")).To(Succeed())

		remaining, err := st.ListTargets(ctx, store.TargetOpts{})
		Expect(err).ToNot(HaveOccurred())
		Expect(remaining).To(HaveLen(1))
	})
})
