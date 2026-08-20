package probes

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/observe"
	"github.com/flanksource/recon/internal/probe"
)

// probeHost checks one host and reports the best answer.
//
// A bare host is tried over HTTPS and HTTP, and the first scheme that answers is
// the one recorded: a host that redirects HTTP to HTTPS is up, and reporting the
// HTTP leg's redirect as its status would be a worse description of it.
func probeHost(ctx context.Context, host string, options probe.Options) api.ProbeResult {
	targets, err := probe.Expand(host)
	if err != nil {
		// Nothing was sent, so there is no transport error to classify: the host
		// as written is not something the prober will fetch.
		return api.ProbeResult{Host: host, Error: err.Error(), Failure: api.FailureOther}
	}

	var last api.ProbeResult
	for _, target := range targets {
		result, err := probe.URL(ctx, target, options)
		converted := api.ProbeResult{
			Host:           host,
			URL:            result.URL,
			Up:             result.Up,
			StatusCode:     result.ResponseCode,
			ResponseTimeMs: result.ResponseTime.Milliseconds(),
			IP:             result.IP,
			ContentType:    result.ContentType,
		}
		if err != nil {
			converted.Error = result.Error
			if converted.Error == "" {
				converted.Error = err.Error()
			}
			converted.Failure = result.Failure
		}
		if converted.Up {
			return converted
		}
		last = converted
	}
	return last
}

// observation projects a result onto what the inventory folds in.
func observation(result api.ProbeResult) observe.Probe {
	found := observe.Probe{
		Host:         result.Host,
		URL:          result.URL,
		IP:           result.IP,
		StatusCode:   result.StatusCode,
		ContentType:  result.ContentType,
		ResponseTime: time.Duration(result.ResponseTimeMs) * time.Millisecond,
		Failed:       !result.Up,
		Error:        result.Error,
		Failure:      result.Failure,
	}
	found.Scheme, found.Port = schemeAndPort(result.URL)
	return found
}

// schemeAndPort reads the endpoint a probe actually reached, defaulting the
// port to the scheme's when the URL leaves it implicit.
func schemeAndPort(rawURL string) (string, int) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return "", 0
	}
	if named := parsed.Port(); named != "" {
		port, err := strconv.Atoi(named)
		if err != nil {
			return parsed.Scheme, 0
		}
		return parsed.Scheme, port
	}
	if parsed.Scheme == "https" {
		return parsed.Scheme, 443
	}
	return parsed.Scheme, 80
}
