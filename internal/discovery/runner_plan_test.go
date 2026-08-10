package discovery

import (
	"io"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/engines"
	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
)

type planEngine struct {
	name  string
	emits enginediscovery.Kind
}

func (e planEngine) Spec() engines.Spec {
	return engines.Spec{Name: e.name, Binary: e.name, Title: e.name}
}
func (e planEngine) Accepts() enginediscovery.Kind                                 { return enginediscovery.Hosts }
func (e planEngine) Emits() enginediscovery.Kind                                   { return e.emits }
func (e planEngine) Args(engines.Run) []string                                     { return nil }
func (e planEngine) Parse(_ io.Reader, _ func(enginediscovery.Record) error) error { return nil }

var _ = Describe("planning discovery execution", func() {
	DescribeTable("chooses a chain from the input",
		func(opts Options, expected string) {
			mode, err := modeFor(opts)
			Expect(err).ToNot(HaveOccurred())
			Expect(mode).To(Equal(expected))
		},
		Entry("configured zones when no input is given", Options{}, ChainFull),
		Entry("targeted probing for inventory hosts", Options{Hosts: []string{"a.example.test"}}, ChainTargeted),
		Entry("explicit probing for a host", Options{Explicit: true, Hosts: []string{"a.example.test"}}, ChainExplicit),
		Entry("explicit enumeration for a domain", Options{Domains: []string{"example.test"}}, ChainExplicit),
		Entry("explicit probing for a CIDR", Options{CIDRs: []string{"192.0.2.0/24"}}, ChainExplicit),
	)

	It("preflights every engine needed by a mixed explicit request", func() {
		Expect(requiredEngines(ChainExplicit, true)).To(Equal(
			[]string{"subfinder", "naabu", "httpx", "tlsx"},
		))
	})

	It("retains enumerated hosts and aggregates endpoint details by host", func() {
		findings := discoveryFindings([]Stage{
			{
				Engine: planEngine{name: "subfinder", emits: enginediscovery.Hosts},
				Hosts:  []string{"enumerated.example.test"},
			},
			{
				Engine: planEngine{name: "naabu", emits: enginediscovery.Endpoints},
				Records: []enginediscovery.Record{
					{Host: "app.example.test", Fields: map[string]any{"port": 8443, "ip": "192.0.2.10"}},
					{Host: "app.example.test", Fields: map[string]any{"port": 443, "ip": "192.0.2.10"}},
				},
			},
			{
				Engine: planEngine{name: "httpx", emits: enginediscovery.Observations},
				Records: []enginediscovery.Record{{
					Host: "app.example.test", Fields: map[string]any{
						"input": "app.example.test", "url": "https://app.example.test:8443",
					},
				}},
			},
		})

		Expect(findings).To(HaveKey("enumerated.example.test"))
		Expect(findings["app.example.test"].Ports).To(Equal([]int{443, 8443}))
		Expect(findings["app.example.test"].IP).To(Equal("192.0.2.10"))
		Expect(findings["app.example.test"].Observations).To(HaveLen(1))
	})

	It("uses the full request as the singleflight identity", func() {
		first, err := runKey(Options{Profile: "one", Hosts: []string{"a.example.test"}})
		Expect(err).ToNot(HaveOccurred())
		same, err := runKey(Options{Profile: "one", Hosts: []string{"a.example.test", "a.example.test"}})
		Expect(err).ToNot(HaveOccurred())
		otherProfile, err := runKey(Options{Profile: "two", Hosts: []string{"a.example.test"}})
		Expect(err).ToNot(HaveOccurred())
		otherHost, err := runKey(Options{Profile: "one", Hosts: []string{"b.example.test"}})
		Expect(err).ToNot(HaveOccurred())

		Expect(first).To(Equal(same))
		Expect(first).ToNot(Equal(otherProfile))
		Expect(first).ToNot(Equal(otherHost))
	})
})
