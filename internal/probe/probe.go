// Package probe performs HTTP(S) liveness checks.
//
// It is the one prober in the codebase: `reconctl ping` reports what it saw and
// throws it away, while probing the inventory folds the same result into each
// target's observed state. Two implementations would drift, and then "ping says
// it is up but the inventory says it is down" would be a question about which
// code ran rather than about the host.
package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/flanksource/clicky"
	"github.com/flanksource/clicky/api"
	commonshttp "github.com/flanksource/commons/http"
)

// Result is one probe of one URL.
type Result struct {
	Up            bool          `json:"up"`
	URL           string        `json:"url"`
	FinalURL      string        `json:"final_url,omitempty"`
	IP            string        `json:"ip,omitempty"`
	TLSCN         string        `json:"tls_cn,omitempty"`
	ResponseCode  int           `json:"response_code,omitempty"`
	ContentType   string        `json:"content_type,omitempty"`
	ContentLength *int64        `json:"content_length,omitempty"`
	ResponseTime  time.Duration `json:"response_time"`
	ResponseSize  int64         `json:"response_size,omitempty"`
	Error         string        `json:"error,omitempty"`
}

var _ api.TableProvider = Result{}

// Columns renders a probe as the table `reconctl ping` prints.
func (Result) Columns() []api.ColumnDef {
	return []api.ColumnDef{
		api.Column("up").Label("Up").Build(),
		api.Column("url").Label("URL").Build(),
		api.Column("final_url").Label("Final URL").Build(),
		api.Column("ip").Label("IP").Build(),
		api.Column("tls_cn").Label("TLS CN").Build(),
		api.Column("response_code").Label("Response Code").Build(),
		api.Column("content_type").Label("Content Type").Build(),
		api.Column("content_length").Label("Content Length").Build(),
		api.Column("response_time").Label("Response Time").Build(),
		api.Column("response_size").Label("Response Size").Build(),
		api.Column("error").Label("Error").Build(),
	}
}

// Row is the rendered form of one probe.
func (r Result) Row() map[string]any {
	row := map[string]any{
		"up":            r.Up,
		"url":           r.URL,
		"final_url":     r.FinalURL,
		"ip":            r.IP,
		"tls_cn":        r.TLSCN,
		"response_code": r.ResponseCode,
		"content_type":  r.ContentType,
		"response_time": clicky.Human(r.ResponseTime),
		"error":         r.Error,
	}
	if r.ContentLength != nil {
		row["content_length"] = api.HumanizeBytes(*r.ContentLength)
	} else {
		row["content_length"] = nil
	}
	if r.ResponseCode > 0 {
		row["response_size"] = api.HumanizeBytes(r.ResponseSize)
	} else {
		row["response_size"] = nil
	}
	return row
}

// Options parameterise one probe.
type Options struct {
	Timeout         time.Duration
	FollowRedirects bool
}

// URL probes one URL and reports what answered.
func URL(ctx context.Context, target string, options Options) (Result, error) {
	started := time.Now()
	result := Result{URL: target}
	trace := &httptrace.ClientTrace{ConnectDone: func(_, address string, err error) {
		if err == nil {
			result.IP = addressIP(address)
		}
	}}
	ctx = httptrace.WithClientTrace(ctx, trace)

	client, err := commonshttp.NewClient().Timeout(options.Timeout).Retry(0, 0, 0).ConnectTimeout(options.Timeout)
	if err != nil {
		return failed(result, started, fmt.Errorf("configure HTTP client: %w", err))
	}
	client, err = client.TLSConfig(commonshttp.TLSConfig{HandshakeTimeout: options.Timeout})
	if err != nil {
		return failed(result, started, fmt.Errorf("configure HTTP client: %w", err))
	}
	if !options.FollowRedirects {
		client.RedirectPolicy(0)
	}
	response, err := client.R(ctx).Get(target)
	if err != nil {
		return failed(result, started, err)
	}

	result.ResponseCode = response.StatusCode
	result.TLSCN = commonName(response.TLS)
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
		return failed(result, started, fmt.Errorf("read response body: %w", err))
	}
	if closeErr != nil {
		return failed(result, started, fmt.Errorf("close response body: %w", closeErr))
	}
	if !Successful(response.StatusCode) {
		return failed(result, started, fmt.Errorf("HTTP status %s", response.Status))
	}
	result.ResponseTime = time.Since(started)
	result.Up = true
	return result, nil
}

// Successful reports whether a status code means the host answered properly.
func Successful(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

// Expand turns one input into the URLs to try: an explicit URL as given, a bare
// host as both HTTPS and HTTP.
func Expand(input string) ([]string, error) {
	if strings.Contains(input, "://") {
		target, err := ValidateURL(input)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", input, err)
		}
		return []string{target}, nil
	}

	targets := make([]string, 0, 2)
	for _, scheme := range []string{"https", "http"} {
		target, err := ValidateURL(scheme + "://" + input)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", input, err)
		}
		targets = append(targets, target)
	}
	return targets, nil
}

// ValidateURL rejects anything the prober will not fetch.
func ValidateURL(input string) (string, error) {
	parsed, err := url.Parse(input)
	if err != nil {
		return "", err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", fmt.Errorf("URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("URL userinfo is not supported")
	}
	return parsed.String(), nil
}

func failed(result Result, started time.Time, err error) (Result, error) {
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

func commonName(state *tls.ConnectionState) string {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}
