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

func kind(value api.TargetKind) func(*api.TargetDocument) {
	return func(d *api.TargetDocument) { d.Kind = value }
}

var _ = Describe("cloud accounts in the inventory", Ordered, Label("db"), func() {
	const (
		prodProject    = "acme-platform-prod"
		sandboxProject = "acme-platform-sandbox"
		liveHost       = "a.accounts.test"
	)

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
			Name:        "recon_accounts",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()

		for _, document := range []api.TargetDocument{
			target(liveHost, api.ClassProd, ports(443), http(200, "https://"+liveHost)),
			target(prodProject, api.ClassProd, kind(api.KindGCPProject), profiles("gcp-cis")),
			target(sandboxProject, api.ClassNonProd, kind(api.KindGCPProject), profiles("gcp-cis")),
		} {
			Expect(st.SaveTarget(ctx, document)).To(Succeed(), document.Host)
		}
	})

	names := func(endpoints []store.Endpoint) []string {
		var found []string
		for _, endpoint := range endpoints {
			found = append(found, endpoint.Host)
		}
		return found
	}

	Describe("Endpoints", func() {
		It("never resolves a cloud account to an address", func() {
			// This is the guard that matters: a project id handed to a network
			// scanner is a hostname that does not exist, and the scan would
			// report a clean result for an account nobody audited.
			endpoints, err := st.Endpoints(ctx, store.TargetOpts{})

			Expect(err).ToNot(HaveOccurred())
			Expect(names(endpoints)).To(Equal([]string{liveHost}))
		})

		It("resolves nothing when the selector names only accounts", func() {
			endpoints, err := st.Endpoints(ctx, store.TargetOpts{Hosts: []string{prodProject}})

			Expect(err).ToNot(HaveOccurred())
			Expect(endpoints).To(BeEmpty())
		})
	})

	Describe("Accounts", func() {
		It("returns every cloud account and no hosts", func() {
			accounts, err := st.Accounts(ctx, store.TargetOpts{})

			Expect(err).ToNot(HaveOccurred())
			Expect(names(accounts)).To(Equal([]string{prodProject, sandboxProject}))
		})

		It("addresses an account by the transport its engine connects through", func() {
			// The rendered input list is a run artifact someone re-runs the tool
			// against by hand, so it holds something pasteable rather than a
			// bare id whose provider has to be guessed.
			accounts, err := st.Accounts(ctx, store.TargetOpts{Hosts: []string{prodProject}})

			Expect(err).ToNot(HaveOccurred())
			Expect(accounts).To(Equal([]store.Endpoint{{
				Host: prodProject, Scheme: "gcp", URL: "gcp://" + prodProject, Class: api.ClassProd,
			}}))
		})

		It("carries the class through for the risk gate", func() {
			// The gate is decided per subject, and a production project is as
			// risky to touch as a production host.
			accounts, err := st.Accounts(ctx, store.TargetOpts{})

			Expect(err).ToNot(HaveOccurred())
			Expect(store.Hosts(store.Risky(accounts))).To(Equal([]string{prodProject}))
		})

		It("narrows on the same selector every other surface uses", func() {
			accounts, err := st.Accounts(ctx, store.TargetOpts{Class: []string{"non-prod"}})

			Expect(err).ToNot(HaveOccurred())
			Expect(names(accounts)).To(Equal([]string{sandboxProject}))
		})

		It("ignores a kind the caller asked for", func() {
			// Asking for accounts and getting hosts back would put hostnames in
			// front of an engine that would audit them as projects.
			accounts, err := st.Accounts(ctx,
				store.TargetOpts{Kind: []string{string(api.KindHost)}})

			Expect(err).ToNot(HaveOccurred())
			Expect(names(accounts)).To(Equal([]string{prodProject, sandboxProject}))
		})
	})

	Describe("the kind selector", func() {
		It("filters the inventory listing", func() {
			found, err := st.ListTargets(ctx, store.TargetOpts{Kind: []string{string(api.KindGCPProject)}})

			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(HaveLen(2))
		})

		It("rejects a kind that is not one of the two", func() {
			_, err := st.ListTargets(ctx, store.TargetOpts{Kind: []string{"aws-account"}})

			Expect(err).To(MatchError(ContainSubstring("unknown kind")))
		})

		It("counts towards a selector being non-empty", func() {
			// An empty selector scans the whole inventory, which is worth
			// saying out loud before it runs — so a kind-only selector must not
			// read as "everything".
			Expect(store.TargetOpts{Kind: []string{string(api.KindHost)}}.Empty()).To(BeFalse())
		})
	})

	Describe("the database", func() {
		It("refuses ports on a cloud account", func() {
			// A port on an account would resolve to an endpoint that does not
			// exist. The schema says so, and this is the last line of defence.
			account := target("acme-platform-broken", api.ClassProd,
				kind(api.KindGCPProject), profiles("gcp-cis"), ports(443))

			Expect(st.SaveTarget(ctx, account)).ToNot(Succeed())
		})
	})
})
