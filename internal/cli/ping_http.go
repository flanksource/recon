package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"time"

	commonshttp "github.com/flanksource/commons/http"
)

type pingProbeOptions struct {
	Timeout         time.Duration
	FollowRedirects bool
}

func probeURL(ctx context.Context, target string, options pingProbeOptions) (PingResult, error) {
	started := time.Now()
	result := PingResult{URL: target}
	trace := &httptrace.ClientTrace{ConnectDone: func(_, address string, err error) {
		if err == nil {
			result.IP = addressIP(address)
		}
	}}
	ctx = httptrace.WithClientTrace(ctx, trace)

	client, err := commonshttp.NewClient().Timeout(options.Timeout).Retry(0, 0, 0).ConnectTimeout(options.Timeout)
	if err != nil {
		return failedPing(result, started, fmt.Errorf("configure HTTP client: %w", err))
	}
	client, err = client.TLSConfig(commonshttp.TLSConfig{
		HandshakeTimeout: options.Timeout,
	})
	if err != nil {
		return failedPing(result, started, fmt.Errorf("configure HTTP client: %w", err))
	}
	if !options.FollowRedirects {
		client.RedirectPolicy(0)
	}
	response, err := client.R(ctx).Get(target)
	if err != nil {
		return failedPing(result, started, err)
	}

	result.ResponseCode = response.StatusCode
	result.TLSCN = tlsCommonName(response.TLS)
	result.ContentType = response.Header.Get("Content-Type")
	if length := response.ContentLength; length >= 0 {
		result.ContentLength = &length
	}
	if finalURL := response.Response.Request.URL.String(); finalURL != target {
		result.FinalURL = finalURL
	}
	result.ResponseSize, err = io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		return failedPing(result, started, fmt.Errorf("read response body: %w", err))
	}
	if closeErr != nil {
		return failedPing(result, started, fmt.Errorf("close response body: %w", closeErr))
	}
	if !isSuccessfulPingStatus(response.StatusCode) {
		return failedPing(result, started, fmt.Errorf("HTTP status %s", response.Status))
	}
	result.ResponseTime = time.Since(started)
	result.Up = true
	return result, nil
}

func isSuccessfulPingStatus(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

func failedPing(result PingResult, started time.Time, err error) (PingResult, error) {
	result.ResponseTime = time.Since(started)
	result.Error = err.Error()
	return result, fmt.Errorf("probe %s: %w", result.URL, err)
}

func addressIP(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func tlsCommonName(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}
