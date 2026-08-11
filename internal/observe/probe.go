package observe

import (
	"fmt"
	"time"

	"github.com/flanksource/recon/internal/api"
)

// Probe is what an HTTP(S) liveness check learned about one host.
//
// Deliberately narrower than a discovery observation: a ping knows whether the
// host answered and how quickly, and nothing about its technology, certificates
// or open ports.
type Probe struct {
	Host         string
	URL          string
	Scheme       string
	Port         int
	IP           string
	StatusCode   int
	ContentType  string
	Location     string
	ResponseTime time.Duration
	Failed       bool
	Error        string
}

// ApplyProbe folds a liveness check into a target.
//
// Unlike Apply, this merges: it writes only what a probe can actually see and
// leaves technology, TLS, open ports and discovered paths as the engines that
// found them left them. A ping that replaced those sections would quietly erase
// most of what is known about a host every time someone refreshed its status.
func ApplyProbe(target api.TargetDocument, observation Probe, timestamp string) (api.TargetDocument, error) {
	if timestamp == "" {
		return api.TargetDocument{}, fmt.Errorf("probe timestamp is required")
	}
	if observation.Host != target.Host {
		return api.TargetDocument{}, fmt.Errorf("probe host %s does not match %s", observation.Host, target.Host)
	}

	observed := api.Observed{}
	if target.Observed != nil {
		observed = *target.Observed
	}
	observed.LastAttempt = timestamp

	if observation.Failed {
		// Same rule as a failed discovery probe: liveness only. The last
		// successful snapshot is still the best thing known about the host.
		observed.Error = observation.Error
		if observed.Error == "" {
			observed.Error = FailedProbeError
		}
		target.Observed = &observed
		target.HTTP = probedHTTP(target.HTTP, observation, true)
		return target, nil
	}

	if observed.FirstObserved == "" {
		observed.FirstObserved = timestamp
	}
	observed.LastSeen = timestamp
	// Cleared rather than left behind: the host answered, so an error from an
	// earlier attempt is no longer true.
	observed.Error = ""
	target.Observed = &observed
	target.HTTP = probedHTTP(target.HTTP, observation, false)

	if observation.IP != "" {
		network := api.Network{}
		if target.Network != nil {
			network = *target.Network
		}
		network.IP = observation.IP
		target.Network = &network
	}
	return target, nil
}

// probedHTTP updates the fields a probe observed and keeps the rest — the
// title, webserver, known paths and login methods belong to whichever engine
// discovered them.
func probedHTTP(current *api.HTTP, observation Probe, failed bool) *api.HTTP {
	http := api.HTTP{}
	if current != nil {
		http = *current
	}
	http.Failed = &failed
	if failed {
		return &http
	}

	if observation.URL != "" {
		http.URL = observation.URL
	}
	if observation.Scheme != "" {
		http.Scheme = observation.Scheme
	}
	if observation.Port > 0 {
		http.Port = observation.Port
	}
	http.StatusCode = observation.StatusCode
	if observation.ContentType != "" {
		contentType := observation.ContentType
		http.ContentType = &contentType
	}
	if observation.Location != "" {
		location := observation.Location
		http.Location = &location
	}
	// Go's duration form ("310.497ms"), which is what httpx already writes into
	// this field — the column has to read the same whichever probe filled it.
	responseTime := observation.ResponseTime.String()
	http.ResponseTime = &responseTime
	return &http
}
