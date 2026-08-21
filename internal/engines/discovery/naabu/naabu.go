// Package naabu wraps the ProjectDiscovery port scanner. It is the first stage
// of a discovery chain: hosts in, open host:port endpoints out.
package naabu

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/discovery"
)

// Engine is the naabu port scanner.
type Engine struct{}

func init() { discovery.Register(Engine{}) }

// Spec describes naabu.
func (Engine) Spec() engines.Spec {
	return engines.Spec{
		Name:        "naabu",
		Binary:      "naabu",
		Title:       "Naabu",
		Description: "Fast SYN/CONNECT port scanner. Finds which ports a host actually has open.",
		DocsURL:     "https://github.com/projectdiscovery/naabu",
		// naabu publishes a single unversioned checksum file, unlike every other
		// ProjectDiscovery tool.
		Install: engines.WithChecksumFile(
			engines.ProjectDiscovery("naabu"), "naabu-checksums.txt"),
		Version: ">=2.6.1",
		Options: engines.OptionsFromSections(catalog),
		Defaults: engines.DefaultProfile{
			Name: "default",
			Comment: "Bounded port discovery. Deliberately conservative: this runs against\n" +
				"live third-party infrastructure, and a broad scan of a shared CDN edge\n" +
				"is both useless and rude.",
			Config: map[string]any{
				"top-ports":   "100",
				"rate":        250,
				"exclude-cdn": true,
				"retries":     1,
				"timeout":     "5s",
			},
		},
	}
}

// Accepts takes bare hostnames.
func (Engine) Accepts() discovery.Kind { return discovery.Hosts }

// Emits open host:port pairs.
func (Engine) Emits() discovery.Kind { return discovery.Endpoints }

// Args builds the command line.
//
// The input list, output format and stdin handling belong to the runner, not to
// a profile: -no-stdin in particular is not optional, because naabu blocks
// forever on an open stdin pipe when it is spawned without a terminal.
func (Engine) Args(run engines.Run) []string {
	args := []string{
		"-list", run.In,
		"-json",
		"-silent",
		"-no-color",
		"-disable-update-check",
		"-no-stdin",
	}
	return append(args, engines.ConfigArgs(run.Config)...)
}

// record is one line of naabu's JSON output.
type record struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Parse reads naabu's JSON lines, emitting one record per open port.
func (Engine) Parse(r io.Reader, emit func(discovery.Record) error) error {
	return engines.ScanJSONLines(r, func(line []byte) error {
		var decoded record
		if err := json.Unmarshal(line, &decoded); err != nil {
			return fmt.Errorf("naabu: %w", err)
		}

		host := decoded.Host
		if host == "" {
			host = decoded.IP
		}
		if host == "" {
			return fmt.Errorf("naabu: record has neither host nor ip: %s", line)
		}
		if decoded.Port < 1 || decoded.Port > 65535 {
			return fmt.Errorf("naabu: port %d out of range for %s", decoded.Port, host)
		}

		return emit(discovery.Record{
			Host: host,
			Fields: map[string]any{
				"port":     decoded.Port,
				"endpoint": host + ":" + strconv.Itoa(decoded.Port),
				"ip":       decoded.IP,
			},
		})
	})
}
