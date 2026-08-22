package store_test

import (
	"context"
	"testing"

	"github.com/flanksource/commons-db/dbtest"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/mute"
	"github.com/flanksource/recon/internal/schema"
	"github.com/flanksource/recon/internal/store"
)

var _ = Describe("mute rules", Ordered, Label("db"), func() {
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
			Name:        "recon_mutes",
			Provisioner: schema.NewProvisioner(),
		})
		st = store.New(db.Gorm())
		ctx = context.Background()
	})

	AfterEach(func() {
		Expect(db.Gorm().Exec(`DELETE FROM mute_rules`).Error).To(Succeed())
		Expect(db.Gorm().Exec(`DELETE FROM targets`).Error).To(Succeed())
	})

	It("round-trips every dimension", func() {
		saved, err := st.SaveMute(ctx, api.MuteRule{
			Name:      "accepted-open-redirect",
			Comment:   "httpbin is a deliberate fixture",
			Engines:   api.StringList{"nuclei"},
			Targets:   map[string]any{"class": []any{"non-prod"}},
			Resources: api.StringList{"logs-*"},
			Templates: api.StringList{"open-redirect"},
			Tags:      api.StringList{"redirect", "!dos"},
			Severity:  api.StringList{"low", "info"},
			Expr:      `finding.host.endsWith(".example.test")`,
		})
		Expect(err).ToNot(HaveOccurred())

		Expect(saved.Comment).To(Equal("httpbin is a deliberate fixture"))
		Expect(saved.Engines).To(ConsistOf("nuclei"))
		Expect(saved.Targets).To(HaveKey("class"))
		Expect(saved.Resources).To(ConsistOf("logs-*"))
		Expect(saved.Templates).To(ConsistOf("open-redirect"))
		Expect(saved.Tags).To(ConsistOf("redirect", "!dos"))
		Expect(saved.Severity).To(ConsistOf("low", "info"))
		Expect(saved.Expr).To(Equal(`finding.host.endsWith(".example.test")`))
		Expect(saved.Disabled).To(BeFalse())
	})

	It("stores a rule carrying only the fields it needs", func() {
		saved, err := st.SaveMute(ctx, api.MuteRule{
			Name: "minimal", Templates: api.StringList{"open-redirect"},
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(saved.Targets).To(BeEmpty())
		Expect(saved.Engines).To(BeEmpty())
		Expect(saved.Comment).To(BeEmpty())
	})

	It("updates a rule in place rather than adding a second", func() {
		_, err := st.SaveMute(ctx, api.MuteRule{Name: "r", Templates: api.StringList{"a"}})
		Expect(err).ToNot(HaveOccurred())
		_, err = st.SaveMute(ctx, api.MuteRule{Name: "r", Templates: api.StringList{"b"}, Disabled: true})
		Expect(err).ToNot(HaveOccurred())

		rules, err := st.ListMutes(ctx, store.MuteOpts{})
		Expect(err).ToNot(HaveOccurred())
		Expect(rules).To(HaveLen(1))
		Expect(rules[0].Templates).To(ConsistOf("b"))
		Expect(rules[0].Disabled).To(BeTrue())
	})

	Describe("what it refuses to store", func() {
		It("refuses a rule that selects nothing", func() {
			_, err := st.SaveMute(ctx, api.MuteRule{Name: "everything"})
			Expect(err).To(MatchError(ContainSubstring("selects nothing")))
		})

		It("refuses an engine that does not exist", func() {
			_, err := st.SaveMute(ctx, api.MuteRule{
				Name: "typo", Templates: api.StringList{"a"}, Engines: api.StringList{"nuclie"},
			})
			Expect(err).To(MatchError(ContainSubstring("nuclie")))
		})

		// Caught here rather than mid-scan, where the only choices left are to
		// fail a run that worked or to silently mute nothing.
		It("refuses an expression that cannot compile, and says where", func() {
			_, err := st.SaveMute(ctx, api.MuteRule{Name: "broken", Expr: `finding.severity == `})
			Expect(err).To(MatchError(ContainSubstring("invalid expression")))
		})

		It("refuses an expression naming a variable that does not exist", func() {
			_, err := st.SaveMute(ctx, api.MuteRule{Name: "wrong-var", Expr: `target.class == "prod"`})
			Expect(err).To(HaveOccurred())
		})

		It("refuses a target selector it cannot parse", func() {
			_, err := st.SaveMute(ctx, api.MuteRule{
				Name: "bad-class", Targets: map[string]any{"class": []any{"invented"}},
			})
			Expect(err).To(MatchError(ContainSubstring("invented")))
		})

		It("refuses a name that could not be a filename fragment", func() {
			_, err := st.SaveMute(ctx, api.MuteRule{Name: "Bad Name", Templates: api.StringList{"a"}})
			Expect(err).To(MatchError(ContainSubstring("invalid mute rule name")))
		})
	})

	Describe("listing", func() {
		BeforeEach(func() {
			for _, rule := range []api.MuteRule{
				{Name: "any-engine", Templates: api.StringList{"a"}},
				{Name: "nuclei-only", Templates: api.StringList{"b"}, Engines: api.StringList{"nuclei"}},
				{Name: "trivy-only", Templates: api.StringList{"c"}, Engines: api.StringList{"trivy"}},
				{Name: "switched-off", Templates: api.StringList{"d"}, Disabled: true},
			} {
				_, err := st.SaveMute(ctx, rule)
				Expect(err).ToNot(HaveOccurred())
			}
		})

		// A rule naming no engine applies to every engine, so an engine filter
		// that hid it would hide the rules with the widest reach.
		It("includes engine-agnostic rules when filtering by engine", func() {
			rules, err := st.ListMutes(ctx, store.MuteOpts{Engine: []string{"nuclei"}})
			Expect(err).ToNot(HaveOccurred())
			Expect(names(rules)).To(ConsistOf("any-engine", "nuclei-only", "switched-off"))
		})

		It("orders by name so attribution is stable", func() {
			rules, err := st.ListMutes(ctx, store.MuteOpts{})
			Expect(err).ToNot(HaveOccurred())
			Expect(names(rules)).To(Equal([]string{"any-engine", "nuclei-only", "switched-off", "trivy-only"}))
		})

		It("finds the rules that are switched off", func() {
			rules, err := st.ListMutes(ctx, store.MuteOpts{Disabled: true})
			Expect(err).ToNot(HaveOccurred())
			Expect(names(rules)).To(ConsistOf("switched-off"))
		})
	})

	Describe("the rules in force for a run", func() {
		BeforeEach(func() {
			for _, rule := range []api.MuteRule{
				{Name: "any-engine", Templates: api.StringList{"a"}},
				{Name: "nuclei-only", Templates: api.StringList{"b"}, Engines: api.StringList{"nuclei"}},
				{Name: "switched-off", Templates: api.StringList{"d"}, Disabled: true},
			} {
				_, err := st.SaveMute(ctx, rule)
				Expect(err).ToNot(HaveOccurred())
			}
		})

		It("leaves out rules for other engines and rules switched off", func() {
			rules, err := st.MuteRules(ctx, "nuclei")
			Expect(err).ToNot(HaveOccurred())
			Expect(rules).To(HaveLen(2))

			rules, err = st.MuteRules(ctx, "trivy")
			Expect(err).ToNot(HaveOccurred())
			Expect(rules).To(HaveLen(1))
			Expect(rules[0].Name).To(Equal("any-engine"))
		})

		It("leaves an unscoped rule covering every target", func() {
			rules, err := st.MuteRules(ctx, "trivy")
			Expect(err).ToNot(HaveOccurred())
			Expect(rules[0].Scoped()).To(BeFalse())
		})

		It("resolves a target selector to the ids it covers", func() {
			// Creating a target validates the profiles it names, so the catalog
			// the server seeds on startup has to be here too.
			_, err := st.SeedDefaultProfiles(ctx)
			Expect(err).ToNot(HaveOccurred())
			DeferCleanup(func() {
				Expect(db.Gorm().Exec(`DELETE FROM engine_profiles`).Error).To(Succeed())
			})

			host := func(name string, class api.Class) api.NewTarget {
				return api.NewTarget{Host: name, Kind: api.KindHost, Curated: api.Curated{
					Class: class, Profiles: api.StringList{"scan:nuclei:safe"},
				}}
			}
			_, err = st.CreateTarget(ctx, host("kept.example.test", api.ClassNonProd))
			Expect(err).ToNot(HaveOccurred())
			_, err = st.CreateTarget(ctx, host("other.example.test", api.ClassProd))
			Expect(err).ToNot(HaveOccurred())

			_, err = st.SaveMute(ctx, api.MuteRule{
				Name: "non-prod-only", Templates: api.StringList{"a"},
				Targets: map[string]any{"class": []any{"non-prod"}},
			})
			Expect(err).ToNot(HaveOccurred())

			rules, err := st.MuteRules(ctx, "nuclei")
			Expect(err).ToNot(HaveOccurred())

			scoped := byName(rules, "non-prod-only")
			Expect(scoped.Scoped()).To(BeTrue())
			Expect(scoped.Targets).To(ConsistOf("kept.example.test"))
		})

		// An empty resolution scopes the rule to nothing. Were it left nil the
		// rule would silently widen to every target the moment its selector
		// stopped matching.
		It("scopes a rule to nothing when its selector matches nothing", func() {
			_, err := st.SaveMute(ctx, api.MuteRule{
				Name: "matches-nothing", Templates: api.StringList{"a"},
				Targets: map[string]any{"class": []any{"internal"}},
			})
			Expect(err).ToNot(HaveOccurred())

			rules, err := st.MuteRules(ctx, "nuclei")
			Expect(err).ToNot(HaveOccurred())

			scoped := byName(rules, "matches-nothing")
			Expect(scoped.Scoped()).To(BeTrue())
			Expect(scoped.Targets).To(BeEmpty())
		})
	})

	It("reports a rule that is not there", func() {
		_, err := st.GetMute(ctx, "absent")
		Expect(err).To(HaveOccurred())
		Expect(st.DeleteMute(ctx, "absent")).ToNot(Succeed())
	})
})

func names(rules []api.MuteRule) []string {
	found := make([]string, 0, len(rules))
	for _, rule := range rules {
		found = append(found, rule.Name)
	}
	return found
}

func byName(rules []mute.Rule, name string) mute.Rule {
	GinkgoHelper()
	for _, rule := range rules {
		if rule.Name == name {
			return rule
		}
	}
	Fail("no mute rule named " + name)
	return mute.Rule{}
}
