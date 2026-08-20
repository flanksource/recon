package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"syscall"

	"github.com/flanksource/recon/internal/api"
)

// Classify says why a probe failed.
//
// Read from the typed error chain rather than by matching the message: Go's
// wording for these is not part of its compatibility promise, and a phrase that
// changes in a release would silently reclassify every dead host in the
// inventory.
//
// Order is not arbitrary. A lookup failure arrives wrapped in a *net.OpError
// whose Op is "dial", and a DNS server that never answered is both a DNS error
// and a timeout — asking the most specific question first is what makes the
// answer the useful one.
func Classify(err error) api.Failure {
	if err == nil {
		return api.FailureNone
	}

	var dns *net.DNSError
	if errors.As(err, &dns) {
		return api.FailureDNS
	}
	if isTLS(err) {
		return api.FailureTLS
	}
	if isTimeout(err) {
		return api.FailureTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return api.FailureRefused
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return api.FailureUnreachable
	}
	return api.FailureOther
}

// isTLS covers the three shapes a rejected handshake takes: the peer's chain was
// not acceptable, its certificate did not verify, or what came back was not TLS
// at all — which is what plain HTTP on an HTTPS port looks like from here.
func isTLS(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &hostname) ||
		errors.As(err, &invalid) ||
		errors.As(err, &verification) ||
		errors.As(err, &record)
}

// isTimeout asks the error itself before asking the clock: a cancelled context
// and an expired deadline both surface here, and net.Error is what every
// transport-level timeout implements.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var timeout net.Error
	return errors.As(err, &timeout) && timeout.Timeout()
}
