package probes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/probe"
)

var _ = Describe("probing one host", func() {
	options := probe.Options{Timeout: 2 * time.Second, FollowRedirects: true}

	It("reports what answered", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
		}))
		DeferCleanup(server.Close)

		// The bare host:port form is what the inventory holds, and it is what
		// Expand turns into an https attempt followed by an http one.
		result := probeHost(context.Background(), hostPort(server.URL), options)

		Expect(result.Up).To(BeTrue(), result.Error)
		Expect(result.StatusCode).To(Equal(http.StatusOK))
		Expect(result.ContentType).To(HavePrefix("text/plain"))
		Expect(result.Host).To(Equal(hostPort(server.URL)))
	})

	It("keeps the host it was asked about, not the URL that answered", func() {
		// The inventory is keyed by host. A result that named the scheme-qualified
		// URL instead could not be folded back into the target it came from.
		result := probeHost(context.Background(), "no-such-host.invalid", options)

		Expect(result.Host).To(Equal("no-such-host.invalid"))
		Expect(result.Up).To(BeFalse())
		Expect(result.Error).ToNot(BeEmpty())
	})

	It("reports the last leg when neither scheme answered", func() {
		result := probeHost(context.Background(), "no-such-host.invalid", options)

		// Expand tries https then http, so the surviving result is the http one.
		Expect(result.URL).To(HavePrefix("http://"))
		Expect(result.Error).ToNot(BeEmpty())
	})

	It("refuses a host it cannot turn into a URL", func() {
		result := probeHost(context.Background(), "http://", options)

		Expect(result.Up).To(BeFalse())
		Expect(result.Error).To(ContainSubstring("must include a host"))
	})
})

var _ = Describe("reading the endpoint a probe reached", func() {
	DescribeTable("defaults the port to the scheme's when the URL leaves it implicit",
		func(url, scheme string, port int) {
			gotScheme, gotPort := schemeAndPort(url)
			Expect([]any{gotScheme, gotPort}).To(Equal([]any{scheme, port}))
		},
		Entry("explicit port", "https://a.example.test:8443/", "https", 8443),
		Entry("implicit https", "https://a.example.test/", "https", 443),
		Entry("implicit http", "http://a.example.test/", "http", 80),
		Entry("no scheme at all", "a.example.test", "", 0),
	)
})

var _ = Describe("the observation a probe folds into a target", func() {
	It("records a failure as failed rather than as an absent status", func() {
		// observe.ApplyProbe branches on Failed, so a probe that could not reach a
		// host must not look like one that reached it and saw a zero status.
		found := observation(probeResultDown("a.example.test", "connection refused"))

		Expect(found.Failed).To(BeTrue())
		Expect(found.Error).To(Equal("connection refused"))
		Expect(found.Host).To(Equal("a.example.test"))
	})
})
