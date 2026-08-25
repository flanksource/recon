package prowler

import (
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// The parser against a whole real report, rather than a hand-written record.
//
// Opt-in through RECON_OCSF_CORPUS, because the reports live in results/ and are
// not committed: they name real projects. The synthetic specs in ocsf_test.go
// prove each rule in isolation; this one proves they compose over 190 records
// that a provider actually emitted — which is where the counts in the design
// came from, and the only place a normalisation rule that is subtly too eager
// shows up as the wrong number.
//
//	RECON_OCSF_CORPUS=results/prowler/…/prowler-output-default-….ocsf.json \
//	  go test ./internal/engines/scan/prowler -run TestProwler
var _ = Describe("the parser over a whole provider report", func() {
	var report ocsfReport

	BeforeEach(func() {
		path := os.Getenv("RECON_OCSF_CORPUS")
		if path == "" {
			Skip("set RECON_OCSF_CORPUS to a prowler OCSF report")
		}
		var err error
		report, err = readOCSF(path, "gcp-prod", "gcp")
		Expect(err).ToNot(HaveOccurred())
	})

	It("names one resource per subject, not one per check", func() {
		resources := report.Resources()
		Expect(resources).ToNot(BeEmpty())
		// Reported rather than asserted: the number belongs to the report, and
		// hard-coding one would make this spec fail on the next scan rather
		// than on a regression. Compare it against `go run ./hack/ocsf-census`,
		// which counts the same file without going through this parser.
		AddReportEntry("resources", len(resources))
		AddReportEntry("findings", len(report.Findings))

		// The key is (provider, scope, uid) and nothing else. If type were in
		// it, the account's per-service pseudo-resources would split one
		// project into a row per service; if scope were not, `default` — a VPC
		// in every project — would merge two.
		keys := map[api.ResourceKey]struct{}{}
		for _, resource := range resources {
			keys[resource.Key()] = struct{}{}
		}
		Expect(keys).To(HaveLen(len(resources)), "every emitted resource is a distinct subject")
	})

	It("gives every resource a stable identity and a verdict to be judged by", func() {
		var verdicts int
		for _, resource := range report.Resources() {
			Expect(resource.UID).ToNot(BeEmpty(), "a resource with no uid cannot be addressed")
			Expect(resource.Provider).ToNot(BeEmpty())
			Expect(resource.Key().Validate()).To(Succeed())
			verdicts += len(resource.Passed) + len(resource.Suppressed)
		}
		// The whole reason passes are read. A report where nothing carried a
		// verdict would leave every finding permanently open.
		Expect(verdicts).To(BeNumerically(">", 0))
	})

	It("resolves the account's own pseudo-resources to one row each", func() {
		accounts := map[string]int{}
		for _, resource := range report.Resources() {
			if resource.Kind == api.KindAccount {
				accounts[resource.Scope]++
			}
		}
		for scope, count := range accounts {
			Expect(count).To(Equal(1),
				"%s is one project however many services typed it", scope)
		}
	})

	// Every finding must reach a resource the report also emitted, or the
	// lifecycle silently drops it: an unlinked finding has no state, so it can
	// never be resolved and never appears against the thing it is about.
	It("names, for every finding, a resource the report emitted", func() {
		emitted := map[string]struct{}{}
		for _, resource := range report.Resources() {
			emitted[resource.UID] = struct{}{}
		}
		for _, finding := range report.Findings {
			Expect(finding.Resources).ToNot(BeEmpty(), "%s names nothing", finding.CheckID)
			Expect(emitted).To(HaveKey(finding.Resources[0].UID),
				"%s is about a resource the report never emitted", finding.CheckID)
		}
	})
})
