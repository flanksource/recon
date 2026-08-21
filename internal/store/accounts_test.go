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

var _ = Describe("provider contexts and network targets", Ordered, Label("db"), func() {
	const (
		prodContext    = "gcp-production"
		sandboxContext = "gcp-sandbox"
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
			providerContext(prodContext, "gcp", prodProject, api.ClassProd),
			providerContext(sandboxContext, "gcp", sandboxProject, api.ClassNonProd),
			{
				ID: "github-production", Kind: api.KindProviderContext,
				Provider: "github", CredentialMode: api.CredentialAmbient,
				Arguments: map[string]any{"organizations": []any{"acme"}},
				Class:     api.ClassProd, Profiles: []string{"scan:prowler:github-cis"}, Tags: []string{},
			},
		} {
			Expect(st.SaveTarget(ctx, document)).To(Succeed(), document.GetID())
		}
	})

	names := func(endpoints []store.Endpoint) []string {
		found := make([]string, 0, len(endpoints))
		for _, endpoint := range endpoints {
			found = append(found, endpoint.Host)
		}
		return found
	}

	It("never resolves provider contexts to network addresses", func() {
		endpoints, err := st.Endpoints(ctx, store.TargetOpts{})

		Expect(err).ToNot(HaveOccurred())
		Expect(names(endpoints)).To(Equal([]string{liveHost}))
	})

	It("keeps the compatibility GCP account projection provider-scoped", func() {
		accounts, err := st.Accounts(ctx, store.TargetOpts{})

		Expect(err).ToNot(HaveOccurred())
		Expect(names(accounts)).To(Equal([]string{prodProject, sandboxProject}))
		Expect(accounts[0]).To(Equal(store.Endpoint{
			TargetID: prodContext, Host: prodProject, Scheme: "gcp",
			URL: "gcp://" + prodProject, Class: api.ClassProd,
		}))
	})

	It("selects an account by stable context ID", func() {
		accounts, err := st.Accounts(ctx, store.TargetOpts{IDs: []string{sandboxContext}})

		Expect(err).ToNot(HaveOccurred())
		Expect(names(accounts)).To(Equal([]string{sandboxProject}))
	})

	It("carries class through for the risk gate", func() {
		accounts, err := st.Accounts(ctx, store.TargetOpts{})

		Expect(err).ToNot(HaveOccurred())
		Expect(store.Hosts(store.Risky(accounts))).To(Equal([]string{prodProject}))
	})

	It("filters generic contexts by provider and kind", func() {
		found, err := st.ListTargets(ctx, store.TargetOpts{
			Kind: []string{string(api.KindProviderContext)}, Provider: []string{"github"},
		})

		Expect(err).ToNot(HaveOccurred())
		Expect(found).To(HaveLen(1))
		Expect(found[0].ID).To(Equal("github-production"))
	})

	It("rejects an explicit context for the wrong provider", func() {
		_, err := st.Accounts(ctx, store.TargetOpts{IDs: []string{"github-production"}})

		Expect(err).To(MatchError(ContainSubstring("uses provider github, not gcp")))
	})

	It("rejects ports on a provider context", func() {
		broken := providerContext("gcp-broken", "gcp", "acme-platform-broken", api.ClassProd)
		broken.Ports = []int{443}

		Expect(st.SaveTarget(ctx, broken)).ToNot(Succeed())
	})
})

func providerContext(id, provider, project string, class api.Class) api.TargetDocument {
	return api.TargetDocument{
		ID: id, Kind: api.KindProviderContext, Provider: provider,
		CredentialMode: api.CredentialAmbient,
		Arguments:      map[string]any{"project-ids": []any{project}},
		Class:          class,
		Profiles:       []string{"scan:prowler:" + provider + "-cis"},
		Tags:           []string{},
	}
}
