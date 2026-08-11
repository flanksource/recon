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

// target builds a document with only the fields a selector reads, so each spec
// states exactly what it is filtering on.
func target(host string, class api.Class, build ...func(*api.TargetDocument)) api.TargetDocument {
	document := api.TargetDocument{
		Schema: api.TargetSchemaRef, Version: api.TargetVersion,
		Host: host, Class: class,
		// The schema requires at least one profile, so every target has one
		// unless a spec overrides it.
		Profiles: []string{"safe"}, Tags: []string{},
	}
	for _, apply := range build {
		apply(&document)
	}
	return document
}

func tags(values ...string) func(*api.TargetDocument) {
	return func(d *api.TargetDocument) { d.Tags = values }
}

func profiles(values ...string) func(*api.TargetDocument) {
	return func(d *api.TargetDocument) { d.Profiles = values }
}

func ports(values ...int) func(*api.TargetDocument) {
	return func(d *api.TargetDocument) { d.Ports = values }
}

func http(status int, url string) func(*api.TargetDocument) {
	return func(d *api.TargetDocument) {
		d.HTTP = &api.HTTP{URL: url, Scheme: "https", Port: 443, StatusCode: status}
	}
}

func openPorts(values ...int) func(*api.TargetDocument) {
	return func(d *api.TargetDocument) { d.Network = &api.Network{OpenPorts: values} }
}

func seen(at string) func(*api.TargetDocument) {
	return func(d *api.TargetDocument) { d.Observed = &api.Observed{LastSeen: at} }
}

var _ = Describe("the target selector", Ordered, Label("db"), func() {
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
			Name:        "recon_opts",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()

		for _, document := range []api.TargetDocument{
			target("a.example.test", api.ClassProd,
				tags("http", "edge", "env=prod", "tier=frontend"), profiles("safe"), ports(443),
				http(200, "https://a.example.test"), seen("2026-08-01T00:00:00Z")),
			target("b.example.test", api.ClassNonProd,
				tags("http", "env=staging", "tier=api"), profiles("safe", "full"), openPorts(443, 8443),
				http(403, "https://b.example.test"), seen("2026-01-01T00:00:00Z")),
			target("c.example.test", api.ClassNonProd,
				tags("internal"), ports(22)),
			target("d.example.test", api.ClassDeactivated,
				func(d *api.TargetDocument) { d.Reason = "decommissioned" }),
		} {
			Expect(st.SaveTarget(ctx, document)).To(Succeed(), document.Host)
		}
	})

	hosts := func(opts store.TargetOpts) []string {
		found, err := st.ListTargets(ctx, opts)
		Expect(err).ToNot(HaveOccurred())
		var names []string
		for _, document := range found {
			names = append(names, document.Host)
		}
		return names
	}

	It("returns everything when nothing is selected", func() {
		Expect(hosts(store.TargetOpts{})).To(HaveLen(4))
	})

	It("filters by class", func() {
		Expect(hosts(store.TargetOpts{Class: []string{"non-prod"}})).
			To(Equal([]string{"b.example.test", "c.example.test"}))
	})

	It("treats several classes as any-of", func() {
		Expect(hosts(store.TargetOpts{Class: []string{"prod", "deactivated"}})).
			To(Equal([]string{"a.example.test", "d.example.test"}))
	})

	It("filters by tag, matching any", func() {
		Expect(hosts(store.TargetOpts{Tags: []string{"http"}})).
			To(Equal([]string{"a.example.test", "b.example.test"}))
		Expect(hosts(store.TargetOpts{Tags: []string{"edge", "internal"}})).
			To(Equal([]string{"a.example.test", "c.example.test"}))
	})

	// What the tri-state filter control sends when a tag is switched to
	// "exclude". It has to narrow in SQL exactly as it does in the in-memory
	// template filter, or the same chip would mean two different things
	// depending on which listing it is on.
	It("excludes a tag prefixed with !", func() {
		Expect(hosts(store.TargetOpts{Tags: []string{"!http"}})).
			To(Equal([]string{"c.example.test", "d.example.test"}))
	})

	It("drops a target carrying an excluded tag even when another tag was included", func() {
		Expect(hosts(store.TargetOpts{Tags: []string{"http", "!edge"}})).
			To(Equal([]string{"b.example.test"}))
	})

	It("keeps a target with no tags at all out of the way of an exclusion", func() {
		// d has no tags, so "not tagged edge" is true of it.
		Expect(hosts(store.TargetOpts{Tags: []string{"!edge"}})).
			To(ContainElement("d.example.test"))
	})

	It("filters tags with Kubernetes selector semantics", func() {
		Expect(hosts(store.TargetOpts{Selector: "http,env=prod,tier in (frontend,api)"})).
			To(Equal([]string{"a.example.test"}))
		Expect(hosts(store.TargetOpts{Selector: "!edge,env,env!=prod"})).
			To(Equal([]string{"b.example.test"}))
	})

	It("rejects an invalid Kubernetes selector", func() {
		_, err := st.ListTargets(ctx, store.TargetOpts{Selector: "env in ("})
		Expect(err).To(MatchError(ContainSubstring("selector")))
	})

	It("filters by assigned profile", func() {
		Expect(hosts(store.TargetOpts{Profiles: []string{"full"}})).
			To(Equal([]string{"b.example.test"}))
	})

	It("combines predicates with AND", func() {
		Expect(hosts(store.TargetOpts{Class: []string{"non-prod"}, Tags: []string{"http"}})).
			To(Equal([]string{"b.example.test"}))
	})

	It("filters by curated port", func() {
		Expect(hosts(store.TargetOpts{Ports: []int{22}})).To(Equal([]string{"c.example.test"}))
	})

	It("filters by last HTTP status", func() {
		Expect(hosts(store.TargetOpts{Status: []int{403}})).To(Equal([]string{"b.example.test"}))
	})

	It("filters to hosts that answered", func() {
		Expect(hosts(store.TargetOpts{Live: true})).
			To(Equal([]string{"a.example.test", "b.example.test"}))
	})

	It("filters by an absolute last-seen time", func() {
		Expect(hosts(store.TargetOpts{LastSeen: "2026-06-01T00:00:00Z"})).
			To(Equal([]string{"a.example.test"}))
	})

	It("names an exact set of hosts", func() {
		Expect(hosts(store.TargetOpts{Hosts: []string{"c.example.test", "a.example.test"}})).
			To(Equal([]string{"a.example.test", "c.example.test"}), "results stay host-ordered")
	})

	It("rejects a class that cannot match rather than returning nothing", func() {
		// Silently returning zero rows reads as "the inventory is empty", which
		// is the wrong conclusion to hand someone about to run a scan.
		_, err := st.ListTargets(ctx, store.TargetOpts{Class: []string{"staging"}})
		Expect(err).To(MatchError(ContainSubstring(`unknown class "staging"`)))
	})

	It("rejects an impossible port", func() {
		_, err := st.ListTargets(ctx, store.TargetOpts{Ports: []int{0}})
		Expect(err).To(MatchError(ContainSubstring("out of range")))
	})

	Describe("resolving to endpoints", func() {
		It("prefers the url that actually answered", func() {
			found, err := st.Endpoints(ctx, store.TargetOpts{Hosts: []string{"a.example.test"}})
			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(HaveLen(1))
			Expect(found[0].URL).To(Equal("https://a.example.test"))
			Expect(found[0].Port).To(Equal(443))
		})

		It("expands a host with several open ports into several endpoints", func() {
			found, err := st.Endpoints(ctx, store.TargetOpts{Hosts: []string{"b.example.test"}})
			Expect(err).ToNot(HaveOccurred())

			var urls []string
			for _, endpoint := range found {
				urls = append(urls, endpoint.URL)
			}
			Expect(urls).To(Equal([]string{
				"https://b.example.test",
				"https://b.example.test:8443",
			}))
		})

		It("uses a curated port when nothing has answered", func() {
			found, err := st.Endpoints(ctx, store.TargetOpts{Hosts: []string{"c.example.test"}})
			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(HaveLen(1))
			Expect(found[0].Port).To(Equal(22))
		})

		It("narrows to the ports the selector named", func() {
			found, err := st.Endpoints(ctx, store.TargetOpts{
				Hosts: []string{"b.example.test"}, Ports: []int{8443},
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(found).To(HaveLen(1))
			Expect(found[0].Port).To(Equal(8443))
		})

		It("names the endpoints an intrusive scan would need confirming", func() {
			found, err := st.Endpoints(ctx, store.TargetOpts{Live: true})
			Expect(err).ToNot(HaveOccurred())

			risky := store.Risky(found)
			Expect(store.Hosts(risky)).To(Equal([]string{"a.example.test"}),
				"only the prod host is risky; non-prod is not")
		})
	})
})

var _ = Describe("stored target selectors", func() {
	It("rejects a stored selector with the wrong field type", func() {
		_, err := store.TargetOptsFrom(map[string]any{"ports": "not-a-list"})
		Expect(err).To(MatchError(ContainSubstring("decode stored target selector")))
	})
})

var _ = Describe("Kubernetes tag selectors", func() {
	It("matches bare and key-value tags with label-selector semantics", func() {
		matches, err := (store.TargetOpts{Selector: "http,env=prod,tier in (frontend,api)"}).
			MatchesTags([]string{"http", "env=prod", "tier=frontend"})
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(BeTrue())
	})

	It("supports absence, existence and inequality requirements", func() {
		matches, err := (store.TargetOpts{Selector: "!edge,env,env!=prod"}).
			MatchesTags([]string{"env=staging", "tier=api"})
		Expect(err).ToNot(HaveOccurred())
		Expect(matches).To(BeTrue())
	})

	It("rejects conflicting values for one label key", func() {
		_, err := (store.TargetOpts{Selector: "env"}).MatchesTags([]string{"env=prod", "env=staging"})
		Expect(err).To(MatchError(`conflicting values for tag "env"`))
	})
})
