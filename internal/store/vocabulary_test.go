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

// A filter offers what these queries return. They run against jsonb sections
// and array columns rather than plain columns, which is where a query that
// parses can still be wrong — and a filter whose options are wrong is worse
// than one with none, because it looks authoritative.
var _ = Describe("the filter vocabularies", Ordered, Label("db"), func() {
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
			Name:        "recon_store",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()

		targets := []api.TargetDocument{{
			Host: "api.example.test", Class: api.ClassProd,
			Profiles: []string{"scan:nuclei:safe"}, Tags: []string{"http", "api"},
			Ports:   []int{8443},
			Network: &api.Network{OpenPorts: []int{80, 443}},
			HTTP:    &api.HTTP{URL: "https://api.example.test", Port: 443, StatusCode: 200},
		}, {
			Host: "admin.example.test", Class: api.ClassInternal,
			Profiles: []string{"scan:nuclei:safe", "scan:nuclei:full"}, Tags: []string{"http", "admin"},
			HTTP: &api.HTTP{URL: "https://admin.example.test", Port: 8080, StatusCode: 403},
		}, {
			// No http section at all: a host whose last probe failed. Its ports
			// and status must not appear, and must not break the others.
			Host: "gone.example.test", Class: api.ClassNonProd,
			Profiles: []string{"scan:nuclei:safe"}, Tags: []string{},
			Observed: &api.Observed{LastAttempt: "2026-01-01T00:00:00Z", Error: "no such host"},
		}}
		for _, target := range targets {
			Expect(st.SaveTarget(ctx, target)).To(Succeed(), target.Host)
		}
	})

	AfterAll(func() {
		if st != nil {
			Expect(db.Gorm().Exec(`DELETE FROM targets`).Error).To(Succeed())
		}
	})

	It("offers every tag in use, once each", func() {
		Expect(st.Vocabulary(ctx, store.TargetTags)).To(Equal([]string{"admin", "api", "http"}))
	})

	It("offers every assigned profile", func() {
		Expect(st.Vocabulary(ctx, store.TargetProfiles)).To(Equal([]string{
			"scan:nuclei:full", "scan:nuclei:safe",
		}))
	})

	It("orders hosts by byte value, which is what the listing is ordered by", func() {
		Expect(st.Vocabulary(ctx, store.TargetHosts)).To(Equal([]string{
			"admin.example.test", "api.example.test", "gone.example.test",
		}))
	})

	It("offers stable target IDs independently of addressable hosts", func() {
		Expect(st.Vocabulary(ctx, store.TargetIDs)).To(Equal([]string{
			"admin.example.test", "api.example.test", "gone.example.test",
		}))
		Expect(st.Vocabulary(ctx, store.TargetProviders)).To(BeEmpty())
	})

	// A port is filterable wherever it is known, so the options have to come
	// from all three places the selector matches on — curated, discovered, and
	// the one that answered — or filtering by a port discovery just found would
	// mean typing it blind.
	It("offers curated, discovered and responding ports together, in numeric order", func() {
		Expect(st.Vocabulary(ctx, store.TargetPorts)).To(Equal([]string{
			"80", "443", "8080", "8443",
		}))
	})

	It("offers the status codes that were actually seen", func() {
		Expect(st.Vocabulary(ctx, store.TargetStatus)).To(Equal([]string{"200", "403"}))
	})

	It("returns an empty set rather than null when nothing has run", func() {
		Expect(st.Vocabulary(ctx, store.FindingTemplates)).To(Equal([]string{}))
	})

	It("names a vocabulary it does not have rather than answering with nothing", func() {
		_, err := st.Vocabulary(ctx, store.Vocabulary("target.nonsense"))
		Expect(err).To(MatchError(ContainSubstring(`no vocabulary query for "target.nonsense"`)))
	})

	// Every declared vocabulary is reachable from a filter, and a filter that
	// cannot enumerate is a text box. A typo in the SQL would otherwise surface
	// as an empty dropdown rather than as a failure.
	It("runs every declared query against this schema", func() {
		for _, name := range store.Vocabularies() {
			_, err := st.Vocabulary(ctx, name)
			Expect(err).ToNot(HaveOccurred(), string(name))
		}
	})
})
