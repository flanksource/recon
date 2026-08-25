package discovery

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
)

var _ = Describe("choosing which discovery engines run", func() {
	DescribeTable("orders a chosen set into a runnable pipeline",
		func(chosen, expected []string) {
			Expect(OrderEngines(chosen)).To(Equal(expected))
		},
		Entry("the default full sweep, however it is spelled",
			[]string{"tlsx", "httpx", "naabu", "subfinder"},
			[]string{"subfinder", "naabu", "httpx", "tlsx"}),
		Entry("crawling sits between the port scan and the HTTP probe",
			[]string{"httpx", "katana", "naabu"},
			[]string{"naabu", "katana", "httpx"}),
		Entry("a DNS probe runs alongside the port scan",
			[]string{"httpx", "dnsx", "naabu"},
			[]string{"dnsx", "naabu", "httpx"}),
		Entry("blanks and repeats are dropped",
			[]string{"httpx", "", "naabu", "httpx", " naabu "},
			[]string{"naabu", "httpx"}),
		Entry("an empty selection stays empty", []string{}, []string{}),
	)

	It("refuses an engine that is not registered", func() {
		_, err := OrderEngines([]string{"naabu", "nmap"})
		Expect(err).To(MatchError(ContainSubstring("nmap")))
	})

	// The chain is what decides a selection is runnable; ordering only saves the
	// caller from having to know the order. A stage nothing feeds must still be
	// refused rather than run against an empty input.
	It("leaves a selection nothing can feed for the chain to reject", func() {
		ordered, err := OrderEngines([]string{"httpx", "tlsx"})
		Expect(err).ToNot(HaveOccurred())
		Expect(ordered).To(Equal([]string{"httpx", "tlsx"}))

		_, err = NewChain(ChainTargeted, enginediscovery.Hosts, ordered...)
		Expect(err).To(MatchError(ContainSubstring("httpx consumes endpoints")))
	})

	It("splits an explicit sweep into its enumerating and probing halves", func() {
		enumerate, probe := seedsFromZones([]string{"subfinder", "naabu", "httpx", "tlsx"})
		Expect(enumerate).To(Equal([]string{"subfinder"}))
		Expect(probe).To(Equal([]string{"naabu", "httpx", "tlsx"}))
	})
})

var _ = Describe("layering run-only configuration over a stored profile", func() {
	It("overrides the named keys and leaves the rest of the profile alone", func() {
		stored := map[string]any{"top-ports": "100", "rate": 1000}
		Expect(engines.LayerOverrides(stored, map[string]any{"top-ports": "full"})).To(Equal(
			map[string]any{"top-ports": "full", "rate": 1000},
		))
		// The stored profile is what a later sweep reads back, so a run-only
		// tweak that mutated it would outlive the run it was made for.
		Expect(stored).To(Equal(map[string]any{"top-ports": "100", "rate": 1000}))
	})

	It("returns the profile untouched when nothing is overridden", func() {
		stored := map[string]any{"rate": 1000}
		Expect(engines.LayerOverrides(stored, nil)).To(Equal(stored))
	})
})
