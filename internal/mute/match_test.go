package mute

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/ocsf"
)

// bucket is a Prowler-shaped finding: the host is the cloud account and the
// resource uid is in matched_at. It exists to keep the resource dimension
// honest — a rule naming a bucket must not have to name the account.
var bucket = api.Finding{
	DetectionFinding: ocsf.DetectionFinding{SeverityID: ocsf.SeverityIDHigh},
	TargetID:         "example-project",
	CheckID:          "gcp/bucket_public",
	Host:             "example-project",
	MatchedAt:        "logs-example",
	Tags:             []string{"storage", "public"},
	Resources: []api.ResourceRef{{
		Provider: "gcp", Scope: "example-project", UID: "logs-example", Name: "logs",
	}},
}

// endpoint is a nuclei-shaped finding: the host is a hostname and matched_at is
// the URL that matched.
var endpoint = api.Finding{
	DetectionFinding: ocsf.DetectionFinding{SeverityID: ocsf.SeverityIDLow},
	TargetID:         "api.example.test",
	CheckID:          "open-redirect",
	Host:             "api.example.test",
	MatchedAt:        "https://api.example.test/redirect",
	Tags:             []string{"redirect", "dos"},
}

func rule(built api.MuteRule) Rule { return Rule{MuteRule: built} }

var _ = Describe("matching a finding", func() {
	It("matches a check by name", func() {
		Expect(rule(api.MuteRule{Templates: api.StringList{"gcp/bucket_public"}}).Matches(bucket)).
			To(BeTrue())
		Expect(rule(api.MuteRule{Templates: api.StringList{"gcp/bucket_public"}}).Matches(endpoint)).
			To(BeFalse())
	})

	It("matches a check by glob", func() {
		Expect(rule(api.MuteRule{Templates: api.StringList{"gcp/*"}}).Matches(bucket)).To(BeTrue())
		Expect(rule(api.MuteRule{Templates: api.StringList{"aws/*"}}).Matches(bucket)).To(BeFalse())
	})

	// An empty dimension is unconstrained. Were it unsatisfiable instead, every
	// rule would have to name every dimension and a partly-filled rule would
	// silently match nothing.
	It("ignores a dimension the rule left empty", func() {
		Expect(rule(api.MuteRule{Severity: api.StringList{"high"}}).Matches(bucket)).To(BeTrue())
	})

	It("ANDs across dimensions", func() {
		both := api.MuteRule{Templates: api.StringList{"gcp/*"}, Severity: api.StringList{"high"}}
		Expect(rule(both).Matches(bucket)).To(BeTrue())

		wrongSeverity := api.MuteRule{Templates: api.StringList{"gcp/*"}, Severity: api.StringList{"low"}}
		Expect(rule(wrongSeverity).Matches(bucket)).To(BeFalse())
	})

	It("ORs within a dimension", func() {
		either := api.MuteRule{Severity: api.StringList{"low", "high"}}
		Expect(rule(either).Matches(bucket)).To(BeTrue())
		Expect(rule(either).Matches(endpoint)).To(BeTrue())
	})

	Describe("the resource dimension", func() {
		It("matches an exact canonical resource without colliding across scopes", func() {
			matched := api.MuteRule{ResourceKeys: api.StringList{"gcp/example-project/logs-example"}}
			Expect(rule(matched).Matches(bucket)).To(BeTrue())

			otherScope := bucket
			otherScope.Resources = []api.ResourceRef{{
				Provider: "gcp", Scope: "other-project", UID: "logs-example", Name: "logs",
			}}
			Expect(rule(matched).Matches(otherScope)).To(BeFalse())
		})

		// The account is in Host and the resource uid in MatchedAt, so a rule
		// about one bucket in a project must reach MatchedAt and must not need
		// to name the project.
		It("matches the resource the evidence names, not only the host", func() {
			Expect(rule(api.MuteRule{Resources: api.StringList{"logs-*"}}).Matches(bucket)).To(BeTrue())
			Expect(rule(api.MuteRule{Resources: api.StringList{"other-*"}}).Matches(bucket)).To(BeFalse())
		})

		It("still matches a host, which is what a network finding names", func() {
			Expect(rule(api.MuteRule{Resources: api.StringList{"api.example.test"}}).Matches(endpoint)).
				To(BeTrue())
		})

		// The case that silently failed. Half of Prowler's uids are opaque
		// numbers — a GCP firewall's is 1429543158501771126 — so the only name
		// an operator could write a rule against was one nothing compared.
		It("matches a resource by the human name, not only its opaque uid", func() {
			firewall := bucket
			firewall.MatchedAt = "1429543158501771126"
			firewall.Resources = []api.ResourceRef{{
				UID: "1429543158501771126", Name: "tailscale-router",
				Type: "compute.googleapis.com/Firewall",
			}}

			Expect(rule(api.MuteRule{Resources: api.StringList{"tailscale-*"}}).Matches(firewall)).
				To(BeTrue())
			Expect(rule(api.MuteRule{Resources: api.StringList{"1429543158501771126"}}).Matches(firewall)).
				To(BeTrue(), "the uid a rule written before this change would have named")
		})

		// The no-regression guarantee, and the reason it is worth a spec of its
		// own: adding values to an OR can only widen, and muting drops
		// findings, so a rule that used to match nothing must still match
		// nothing. A finding naming no resource resolves to exactly the two
		// values this dimension compared before.
		It("behaves exactly as before for a finding that names no resource", func() {
			bare := bucket
			bare.Resources = nil

			Expect(rule(api.MuteRule{Resources: api.StringList{"logs-*"}}).Matches(bare)).To(BeTrue())
			Expect(rule(api.MuteRule{Resources: api.StringList{"other-*"}}).Matches(bare)).To(BeFalse())
			Expect(rule(api.MuteRule{Resources: api.StringList{"example-project"}}).Matches(bare)).
				To(BeTrue(), "the host rung, unchanged")
		})
	})

	Describe("the tag dimension", func() {
		It("matches any listed tag", func() {
			Expect(rule(api.MuteRule{Tags: api.StringList{"storage"}}).Matches(bucket)).To(BeTrue())
		})

		// A negated tag excludes the finding outright rather than being ignored
		// because a different tag matched.
		It("excludes a finding carrying a negated tag", func() {
			Expect(rule(api.MuteRule{Tags: api.StringList{"redirect", "!dos"}}).Matches(endpoint)).
				To(BeFalse())
		})

		It("leaves an untagged finding to an exclusion-only filter", func() {
			untagged := api.Finding{
				DetectionFinding: ocsf.DetectionFinding{SeverityID: ocsf.SeverityIDInformational},
				CheckID:          "x",
			}
			Expect(rule(api.MuteRule{Tags: api.StringList{"!dos"}}).Matches(untagged)).To(BeTrue())
		})
	})

	Describe("the target scope", func() {
		It("covers every target when the rule names no selector", func() {
			unscoped := rule(api.MuteRule{Templates: api.StringList{"gcp/*"}})
			Expect(unscoped.Scoped()).To(BeFalse())
			Expect(unscoped.Matches(bucket)).To(BeTrue())
		})

		It("covers only the targets the selector resolved to", func() {
			scoped := Rule{
				MuteRule: api.MuteRule{Templates: api.StringList{"gcp/*"}},
				Targets:  []string{"other-project"},
			}
			Expect(scoped.Matches(bucket)).To(BeFalse())

			scoped.Targets = []string{"example-project"}
			Expect(scoped.Matches(bucket)).To(BeTrue())
		})

		// An empty non-nil set means the selector matched nothing, which is not
		// the same as a rule that named no selector at all.
		It("covers nothing when the selector resolved to nothing", func() {
			resolved := Rule{
				MuteRule: api.MuteRule{Templates: api.StringList{"gcp/*"}},
				Targets:  []string{},
			}
			Expect(resolved.Scoped()).To(BeTrue())
			Expect(resolved.Matches(bucket)).To(BeFalse())
		})
	})

	Describe("the expression", func() {
		It("narrows what the dimensions admitted", func() {
			narrowed := api.MuteRule{
				Templates: api.StringList{"gcp/*"},
				Expr:      `finding.matchedAt.startsWith("logs-")`,
			}
			Expect(rule(narrowed).Matches(bucket)).To(BeTrue())

			narrowed.Expr = `finding.matchedAt.startsWith("data-")`
			Expect(rule(narrowed).Matches(bucket)).To(BeFalse())
		})

		// The expression is evaluated only over findings the structured scope
		// already admitted, so it cannot widen a rule however true it is.
		It("cannot widen a rule past its dimensions", func() {
			widening := api.MuteRule{Templates: api.StringList{"aws/*"}, Expr: `true`}
			Expect(rule(widening).Matches(bucket)).To(BeFalse())
		})

		It("reports a rule it could not evaluate rather than matching", func() {
			matched, err := rule(api.MuteRule{Expr: `finding.host`}).Matches(bucket)
			Expect(err).To(HaveOccurred())
			Expect(matched).To(BeFalse())
		})
	})
})
