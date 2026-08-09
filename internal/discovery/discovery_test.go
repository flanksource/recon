package discovery_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/discovery"
)

func TestDiscovery(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "discovery")
}

// write puts a file in a temporary manifest tree.
func write(dir, name, body string) {
	path := filepath.Join(dir, name)
	Expect(os.MkdirAll(filepath.Dir(path), 0o755)).To(Succeed())
	Expect(os.WriteFile(path, []byte(body), 0o644)).To(Succeed())
}

var _ = Describe("scraping hostnames out of manifests", func() {
	var dir string

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
	})

	scrape := func(zones ...string) []string {
		hosts, err := discovery.StaticScrape{Dirs: []string{dir}, Zones: zones}.Run()
		Expect(err).ToNot(HaveOccurred())
		return hosts
	}

	It("finds Ingress hosts and certificate names", func() {
		write(dir, "ingress.yaml", `
spec:
  rules:
    - host: app.example.test
  tls:
    - hosts:
        - api.example.test
`)
		write(dir, "certificate.yaml", `
spec:
  dnsNames:
    - mail.example.test
`)
		Expect(scrape("example.test")).To(Equal([]string{
			"api.example.test", "app.example.test", "mail.example.test",
		}))
	})

	It("keeps hosts out of scope out of the inventory", func() {
		// A manifest routinely names images, registries and third-party
		// endpoints. Those belong to somebody else and must not be scanned.
		write(dir, "deploy.yaml", `
image: docker.io/library/nginx
host: app.example.test
externalName: storage.googleapis.com
`)
		Expect(scrape("example.test")).To(Equal([]string{"app.example.test"}))
	})

	It("reduces a wildcard certificate to the zone it names", func() {
		write(dir, "wildcard.yaml", "dnsNames:\n  - '*.apps.example.test'\n")
		Expect(scrape("example.test")).To(Equal([]string{"apps.example.test"}))
	})

	It("matches the zone itself, not only its subdomains", func() {
		write(dir, "apex.yaml", "host: example.test\n")
		Expect(scrape("example.test")).To(Equal([]string{"example.test"}))
	})

	It("lowercases and deduplicates across files", func() {
		write(dir, "one.yaml", "host: App.Example.Test\n")
		write(dir, "two/two.yaml", "host: app.example.test.\n")
		Expect(scrape("example.test")).To(Equal([]string{"app.example.test"}))
	})

	It("reads only manifest files", func() {
		write(dir, "README.md", "visit docs.example.test for more\n")
		write(dir, "config.yaml", "host: real.example.test\n")
		Expect(scrape("example.test")).To(Equal([]string{"real.example.test"}))
	})

	It("does not walk into vendored trees", func() {
		write(dir, "node_modules/pkg/config.yaml", "host: vendored.example.test\n")
		write(dir, "config.yaml", "host: real.example.test\n")
		Expect(scrape("example.test")).To(Equal([]string{"real.example.test"}))
	})

	It("refuses to run with no directory configured", func() {
		// Silently finding nothing would read as "no hosts" rather than
		// "this stage was never set up".
		_, err := discovery.StaticScrape{Zones: []string{"example.test"}}.Run()
		Expect(err).To(MatchError(ContainSubstring("no spec directories configured")))
	})

	It("refuses to run with no zones configured", func() {
		_, err := discovery.StaticScrape{Dirs: []string{dir}}.Run()
		Expect(err).To(MatchError(ContainSubstring("no zones configured")))
	})

	It("fails loudly when a configured directory is missing", func() {
		_, err := discovery.StaticScrape{
			Dirs: []string{filepath.Join(dir, "absent")}, Zones: []string{"example.test"},
		}.Run()
		Expect(err).To(HaveOccurred())
	})
})

// stubResolver answers from a table so the specs need no network.
type stubResolver struct {
	ns  map[string][]string
	mx  map[string][]string
	err map[string]error
}

func (s stubResolver) LookupNS(_ context.Context, zone string) ([]*net.NS, error) {
	if err := s.err[zone+"/NS"]; err != nil {
		return nil, err
	}
	var records []*net.NS
	for _, host := range s.ns[zone] {
		records = append(records, &net.NS{Host: host})
	}
	return records, nil
}

func (s stubResolver) LookupMX(_ context.Context, zone string) ([]*net.MX, error) {
	if err := s.err[zone+"/MX"]; err != nil {
		return nil, err
	}
	var records []*net.MX
	for _, host := range s.mx[zone] {
		records = append(records, &net.MX{Host: host})
	}
	return records, nil
}

var _ = Describe("asking DNS for the infrastructure behind a zone", func() {
	ctx := context.Background()

	It("collects nameservers and mail exchangers", func() {
		result, err := discovery.DiscoverDNS(ctx, stubResolver{
			ns: map[string][]string{"example.test": {"ns2.provider.test.", "ns1.provider.test."}},
			mx: map[string][]string{"example.test": {"mail.example.test."}},
		}, []string{"example.test"})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Nameservers).To(Equal([]string{"ns1.provider.test", "ns2.provider.test"}))
		Expect(result.MailExchanges).To(Equal([]string{"mail.example.test"}))
		Expect(result.Hosts).To(Equal([]string{
			"mail.example.test", "ns1.provider.test", "ns2.provider.test",
		}))
	})

	It("ignores the null MX", func() {
		// RFC 7505: "." means the zone accepts no mail. It is not a hostname.
		result, err := discovery.DiscoverDNS(ctx, stubResolver{
			ns: map[string][]string{"example.test": {"ns1.provider.test"}},
			mx: map[string][]string{"example.test": {"."}},
		}, []string{"example.test"})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.MailExchanges).To(BeEmpty())
	})

	It("reports a failed lookup rather than treating it as an empty zone", func() {
		result, err := discovery.DiscoverDNS(ctx, stubResolver{
			ns:  map[string][]string{"example.test": {"ns1.provider.test"}},
			err: map[string]error{"example.test/MX": fmt.Errorf("server misbehaving")},
		}, []string{"example.test"})

		Expect(err).ToNot(HaveOccurred(), "one failed query is not a failed sweep")
		Expect(result.Failures).To(HaveLen(1))
		Expect(result.Failures[0].Record).To(Equal("MX"))
		Expect(result.Nameservers).To(Equal([]string{"ns1.provider.test"}))
	})

	It("fails when every query failed, because that is a broken resolver", func() {
		_, err := discovery.DiscoverDNS(ctx, stubResolver{
			err: map[string]error{
				"example.test/NS": fmt.Errorf("no such host"),
				"example.test/MX": fmt.Errorf("no such host"),
			},
		}, []string{"example.test"})

		Expect(err).To(MatchError(ContainSubstring("all 2 NS/MX queries failed")))
	})

	It("deduplicates and normalises the zones it is given", func() {
		result, err := discovery.DiscoverDNS(ctx, stubResolver{
			ns: map[string][]string{"example.test": {"ns1.provider.test"}},
		}, []string{"Example.Test.", "example.test"})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Nameservers).To(Equal([]string{"ns1.provider.test"}))
	})

	It("refuses a sweep with no zones", func() {
		_, err := discovery.DiscoverDNS(ctx, stubResolver{}, nil)
		Expect(err).To(MatchError(ContainSubstring("at least one zone")))
	})

	It("orders failures so a run's report is diffable", func() {
		result, _ := discovery.DiscoverDNS(ctx, stubResolver{
			ns: map[string][]string{"b.test": {"ns1.provider.test"}},
			err: map[string]error{
				"a.test/NS": fmt.Errorf("x"), "a.test/MX": fmt.Errorf("x"),
				"b.test/MX": fmt.Errorf("x"),
			},
		}, []string{"b.test", "a.test"})

		Expect(result.Failures).To(HaveLen(3))
		Expect(result.Failures[0].Zone).To(Equal("a.test"))
		Expect(result.Failures[0].Record).To(Equal("MX"))
		Expect(result.Failures[1].Record).To(Equal("NS"))
		Expect(result.Failures[2].Zone).To(Equal("b.test"))
	})
})
