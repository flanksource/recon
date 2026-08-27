package api_test

import (
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

func preflight() api.InsightSync {
	return api.InsightSync{
		Server: "https://mc.example.test", Agent: "recon", DryRun: true,
		MatchedResources: 94, MatchedStates: 190, Eligible: 188, Skipped: 2,
		Open: 150, Resolved: 30, Silenced: 8, Direct: 140, RolledUp: 36, Pinned: 12,
		Configs: []api.InsightConfig{
			{ID: "cfg-1", Name: "logs-example", Type: "GCP::Bucket", Insights: 140},
			{ID: "cfg-2", Name: "acme-prod", Type: "GCP::Project", Insights: 36, RolledUp: true, Pinned: true},
		},
		Ambiguous: []api.InsightAmbiguity{{
			Identity: "workload-prod-eu-02", Scope: true, States: 12,
			Resources: []string{"web-1", "web-2"},
			Options: []api.InsightChoice{
				{ID: "eb6a8af6", Name: "workload-prod-eu-02", Type: "GCP::Project"},
				{ID: "03525cee", Name: "workload-prod-eu-02", Type: "Kubernetes::Cluster"},
				{ID: "9f0c1d22", Name: "acme-root", Type: "GCP::Organization", Root: true, Ancestor: true},
			},
		}},
		Unresolved: []api.InsightUnresolved{{
			Finding: "01JSCAN#4", Host: "scratch", Severity: api.SeverityLow,
			Tried: []string{"scratch"}, Reason: "no catalog config item matches",
		}},
	}
}

// The preflight is what a dry run is for, so what it renders is a contract: the
// numbers that say how much would land, and the two lists that explain why it is
// not everything.
var _ = Describe("the sync preflight", func() {
	It("renders the coverage, the undecided identities and how to decide them", func() {
		rendered := preflight().Pretty().String()

		Expect(rendered).To(ContainSubstring("preview insights → https://mc.example.test as recon"))
		Expect(rendered).To(ContainSubstring("190 states over 94 resources · 188 eligible · 2 skipped"))
		Expect(rendered).To(ContainSubstring("176 attached to 2 config items · 140 direct · 36 rolled up · 12 pinned"))
		Expect(rendered).To(ContainSubstring("1 ambiguous identities · 1 unresolved states"))

		Expect(rendered).To(ContainSubstring("workload-prod-eu-02 — 12 states (web-1, web-2)"))
		Expect(rendered).To(ContainSubstring("eb6a8af6  workload-prod-eu-02  GCP::Project"))
		Expect(rendered).To(ContainSubstring("9f0c1d22  acme-root  GCP::Organization  [contains the matches]  [root]"))
		Expect(rendered).To(ContainSubstring("choose with --config workload-prod-eu-02=<config-id>"))

		Expect(rendered).To(ContainSubstring("no catalog config item matches"))
	})

	It("says a run pushed rather than that it would", func() {
		result := preflight()
		result.DryRun, result.Pushed = false, 176

		rendered := result.Pretty().String()

		Expect(rendered).To(ContainSubstring("sync insights → https://mc.example.test as recon"))
		Expect(rendered).To(ContainSubstring("176 insights pushed"))
	})

	// The browser reads this shape; an absent list must be [] rather than null,
	// or every consumer needs its own guard before mapping over it.
	It("serialises the lists a preflight can legitimately leave empty", func() {
		encoded, err := json.Marshal(api.InsightSync{Agent: "recon"})

		Expect(err).ToNot(HaveOccurred())
		Expect(string(encoded)).To(ContainSubstring(`"configs":[]`))
		Expect(string(encoded)).To(ContainSubstring(`"unresolved":[]`))
		Expect(string(encoded)).To(ContainSubstring(`"ambiguous":[]`))
	})
})
