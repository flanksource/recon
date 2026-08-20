package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// The errors a probe actually meets, in the shape the transport hands them
// over: wrapped in a *net.OpError, and wrapped again by the client. Fabricated
// rather than provoked because provoking a route-unreachable or a DNS timeout on
// a developer's machine is not something a test can arrange.
func dialing(err error) error {
	return fmt.Errorf("Get %q: %w", "https://host.example.test", &net.OpError{
		Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, Err: err,
	})
}

var _ = Describe("classifying why a probe failed", func() {
	DescribeTable("reads the error chain, not the message",
		func(err error, expected api.Failure) {
			Expect(Classify(err)).To(Equal(expected))
		},
		Entry("a host that answered", nil, api.FailureNone),
		// The one that has to win over the *net.OpError it arrives wrapped in:
		// "this name does not resolve" and "nothing is listening" have different
		// owners, and reporting the second for the first sends people to the
		// wrong team.
		Entry("a name that does not resolve",
			dialing(&net.DNSError{Err: "no such host", Name: "host.example.test", IsNotFound: true}),
			api.FailureDNS),
		// A DNS server that never answered is both a DNS error and a timeout.
		// Asking the specific question first is what makes the answer useful.
		Entry("a nameserver that did not answer",
			dialing(&net.DNSError{Err: "i/o timeout", Name: "host.example.test", IsTimeout: true}),
			api.FailureDNS),
		Entry("nothing listening", dialing(syscall.ECONNREFUSED), api.FailureRefused),
		Entry("no route to the host", dialing(syscall.EHOSTUNREACH), api.FailureUnreachable),
		Entry("no route to the network", dialing(syscall.ENETUNREACH), api.FailureUnreachable),
		Entry("a deadline the client set", dialing(os.ErrDeadlineExceeded), api.FailureTimeout),
		Entry("a context that expired", context.DeadlineExceeded, api.FailureTimeout),
		Entry("an untrusted chain",
			fmt.Errorf("tls: %w", x509.UnknownAuthorityError{}), api.FailureTLS),
		Entry("a certificate for another name",
			fmt.Errorf("tls: %w", x509.HostnameError{Host: "host.example.test"}), api.FailureTLS),
		Entry("a certificate that did not verify",
			fmt.Errorf("tls: %w", &tls.CertificateVerificationError{}), api.FailureTLS),
		// What plain HTTP on an HTTPS port looks like from here.
		Entry("a peer that did not speak TLS",
			fmt.Errorf("tls: %w", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}),
			api.FailureTLS),
		Entry("something with no known shape", errors.New("nothing recognisable"), api.FailureOther),
	)
})

var _ = Describe("probing an endpoint that does not answer", func() {
	// Provoked rather than fabricated: this is the one failure a test can arrange
	// deterministically, and it proves the classification survives the whole
	// client stack rather than only the errors this file builds by hand.
	It("reports a closed port as refused", func() {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		closed := listener.Addr().String()
		Expect(listener.Close()).To(Succeed())

		result, err := URL(context.Background(), "http://"+closed, Options{Timeout: 2 * time.Second})

		Expect(err).To(HaveOccurred())
		Expect(result.Up).To(BeFalse())
		Expect(result.Failure).To(Equal(api.FailureRefused))
	})

	// The endpoint is up and something above the transport is wrong, which is a
	// different problem from a host that cannot be reached at all.
	It("reports a served error status as an HTTP failure", func() {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		DeferCleanup(server.Close)

		result, err := URL(context.Background(), server.URL, Options{Timeout: 2 * time.Second})

		Expect(err).To(HaveOccurred())
		Expect([]any{result.Failure, result.ResponseCode}).To(Equal([]any{
			api.FailureHTTP, http.StatusBadGateway,
		}))
	})

	It("leaves a host that answered unclassified", func() {
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		DeferCleanup(server.Close)

		result, err := URL(context.Background(), server.URL, Options{Timeout: 2 * time.Second})

		Expect(err).ToNot(HaveOccurred())
		Expect(result.Failure).To(Equal(api.FailureNone))
	})
})
