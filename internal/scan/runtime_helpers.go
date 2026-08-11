package scan

import (
	"fmt"

	"github.com/flanksource/recon/internal/api"
	enginescan "github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/store"
)

// serialEngines names the registered scan engines that cannot run concurrently.
func serialEngines() []string {
	var names []string
	for _, spec := range enginescan.Specs() {
		if spec.InProcess {
			names = append(names, spec.Name)
		}
	}
	return names
}

func selectorMap(opts store.TargetOpts) (*map[string]any, error) {
	stored, err := opts.Map()
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

func hostsOf(findings []api.Finding) []string {
	seen := map[string]bool{}
	var hosts []string
	for _, finding := range findings {
		if finding.Host != "" && !seen[finding.Host] {
			seen[finding.Host] = true
			hosts = append(hosts, finding.Host)
		}
	}
	return hosts
}

// summarise names the first few hosts and counts the rest. A prompt that says
// "3 production hosts" without saying which is not one anyone can answer.
func summarise(hosts []string) string {
	const shown = 3
	if len(hosts) <= shown {
		return joinHosts(hosts)
	}
	return fmt.Sprintf("%s and %d more", joinHosts(hosts[:shown]), len(hosts)-shown)
}

func joinHosts(hosts []string) string {
	out := ""
	for i, host := range hosts {
		if i > 0 {
			out += ", "
		}
		out += host
	}
	return out
}
