package probe

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestProbe(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "probe")
}

var _ = Describe("reading what answered", func() {
	It("extracts the TLS common name and socket IP", func() {
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{
			Subject: pkix.Name{CommonName: "service.example.test"},
		}}}
		Expect(commonName(state)).To(Equal("service.example.test"))
		Expect(commonName(nil)).To(BeEmpty())
		Expect(addressIP("[2001:db8::10]:443")).To(Equal("2001:db8::10"))
	})
})

var _ = Describe("expanding what to probe", func() {
	// A bare host says nothing about its scheme, so both are tried; an explicit
	// URL is taken as given, because guessing would probe something the caller
	// did not name.
	It("tries both schemes for a bare host and only the one given for a URL", func() {
		Expect(Expand("api.example.test")).To(Equal([]string{
			"https://api.example.test", "http://api.example.test",
		}))
		Expect(Expand("http://api.example.test/health")).To(Equal([]string{
			"http://api.example.test/health",
		}))
	})

	DescribeTable("refuses what it will not fetch",
		func(input, reason string) {
			_, err := Expand(input)
			Expect(err).To(MatchError(ContainSubstring(reason)))
		},
		Entry("a scheme it does not speak", "ftp://example.test", "unsupported scheme"),
		Entry("credentials in the URL", "https://user:pw@example.test", "userinfo"),
		Entry("no host at all", "https://", "must include a host"),
	)
})
