// Package tlsx wraps the ProjectDiscovery TLS prober. httpx already grabs a
// certificate in passing; tlsx exists for when TLS posture is the question
// rather than a side effect — expiry sweeps, cipher and protocol audits, and the
// hosts that speak TLS on a port that is not HTTP.
package tlsx

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
)

// Engine is the tlsx prober.
type Engine struct{}

func init() { discovery.Register(Engine{}) }

var catalog = engines.Sections{
	{
		ID:          "probes",
		Title:       "Certificate data",
		Description: "What to read from the certificate and the handshake.",
		SourceURL:   "https://github.com/projectdiscovery/tlsx#usage",
		Properties: []engines.Field{
			engines.Bool("san", "Subject alternative names", "Collect the certificate's SAN entries."),
			engines.Bool("cn", "Common name", "Collect the certificate's common name."),
			engines.Bool("so", "Subject organisation", "Collect the subject organisation."),
			engines.Bool("tls-version", "TLS version", "Report the negotiated protocol version."),
			engines.Bool("cipher", "Cipher", "Report the negotiated cipher suite."),
			engines.Bool("hash", "Fingerprint", "Report the certificate fingerprint."),
			engines.Bool("jarm", "JARM", "Compute the JARM fingerprint. Costs an extra handshake per host."),
			engines.Bool("expired", "Expired", "Flag expired certificates."),
			engines.Bool("self-signed", "Self-signed", "Flag self-signed certificates."),
			engines.Bool("mismatched", "Mismatched", "Flag certificates whose name does not match the host."),
			engines.Bool("revoked", "Revoked", "Check revocation status."),
			engines.Bool("untrusted", "Untrusted", "Flag certificates that do not chain to a trusted root."),
		},
	},
	{
		ID:          "network",
		Title:       "Connection",
		Description: "How the handshake is made.",
		SourceURL:   "https://github.com/projectdiscovery/tlsx#usage",
		Properties: []engines.Field{
			engines.StrList("port", "Ports", "Ports to probe when the input carries none."),
			engines.Enum("min-version", "Minimum version", "Lowest protocol version to offer.", "ssl30", "tls10", "tls11", "tls12", "tls13"),
			engines.Enum("max-version", "Maximum version", "Highest protocol version to offer.", "ssl30", "tls10", "tls11", "tls12", "tls13"),
			engines.Int("timeout", "Timeout", "Seconds to wait for a handshake.", 1),
			engines.Int("retries", "Retries", "Retries per host.", 0),
		},
	},
	{
		ID:          "performance",
		Title:       "Performance",
		Description: "Bound the sweep.",
		SourceURL:   "https://github.com/projectdiscovery/tlsx#usage",
		Properties: []engines.Field{
			engines.Int("concurrency", "Concurrency", "Hosts probed in parallel.", 1),
			engines.Int("rate-limit", "Rate limit", "Handshakes per second.", 1),
		},
	},
}

// Spec describes tlsx.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:        "tlsx",
		Binary:      "tlsx",
		Title:       "tlsx",
		Description: "TLS certificate and configuration prober.",
		DocsURL:     "https://github.com/projectdiscovery/tlsx",
		Install:     engines.ProjectDiscovery("tlsx"),
		Version:     ">=1.3.0",
		Options:     engines.OptionsFromSections(catalog),
		Defaults: engines.DefaultProfile{
			Name: "default",
			Comment: "Certificate posture: identity, validity and the negotiated parameters.\n" +
				"The display probes are deliberately unset. They select columns for\n" +
				"tlsx's text output, and -json already carries every one of those\n" +
				"fields; asking for them alongside anything else makes tlsx refuse to\n" +
				"start with \"san or cn flag cannot be used with other probes\".",
			Config: map[string]any{
				"expired": true, "self-signed": true, "mismatched": true, "untrusted": true,
				"timeout": 10, "concurrency": 50,
			},
		},
	}
}

// Accepts endpoints.
func (Engine) Accepts() discovery.Kind { return discovery.Endpoints }

// Emits observations.
func (Engine) Emits() discovery.Kind { return discovery.Observations }

// Args builds the command line.
func (Engine) Args(run engines.Run) []string {
	args := []string{
		"-list", run.In,
		"-json",
		"-silent",
		"-no-color",
		"-disable-update-check",
	}
	return append(args, engines.ConfigArgs(run.Config)...)
}

// Parse reads tlsx's JSON lines and nests the certificate data under `tls`,
// which is where the observation normaliser expects to find it.
func (Engine) Parse(r io.Reader, emit func(discovery.Record) error) error {
	return engines.ScanJSONLines(r, func(line []byte) error {
		var fields map[string]any
		if err := json.Unmarshal(line, &fields); err != nil {
			return fmt.Errorf("tlsx: %w", err)
		}

		host, _ := fields["host"].(string)
		if host == "" {
			return fmt.Errorf("tlsx: record has no host")
		}

		// tlsx reports certificate fields at the top level, while httpx nests
		// them under `tls`. Reshaping here means one normaliser handles both.
		certificate := map[string]any{}
		for key, value := range fields {
			switch key {
			case "host", "port", "ip", "timestamp":
				continue
			default:
				certificate[key] = value
			}
		}

		return emit(discovery.Record{
			Host: engines.HostOf(host),
			Fields: map[string]any{
				"input": engines.HostOf(host),
				"port":  fields["port"],
				"tls":   certificate,
			},
		})
	})
}
