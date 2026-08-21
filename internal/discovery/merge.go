package discovery

import (
	"context"
	"fmt"
	"sort"
	"time"

	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/observe"
)

func (r *Runner) record(ctx context.Context, discoveryID string, stages []Stage) ([]string, error) {
	var rows []models.DiscoveryHost
	seen := map[string]bool{}
	for _, stage := range stages {
		if stage.Engine == nil {
			continue
		}
		name := stage.Engine.Spec().Name
		for _, host := range stage.Hosts {
			rows = append(rows, models.DiscoveryHost{
				DiscoveryID: discoveryID, Host: host, Engine: name,
				Live: stage.Engine.Emits() == enginediscovery.Observations,
			})
			seen[host] = true
		}
	}
	saveErr := r.Store.SaveDiscoveryHosts(ctx, rows)
	hosts := make([]string, 0, len(seen))
	for host := range seen {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, saveErr
}

type hostFinding struct {
	Observations []map[string]any
	Ports        []int
	IP           string
}

func discoveryFindings(stages []Stage) map[string]hostFinding {
	findings := map[string]hostFinding{}
	for _, stage := range stages {
		if stage.Engine == nil {
			continue
		}
		for _, host := range stage.Hosts {
			if _, ok := findings[host]; !ok {
				findings[host] = hostFinding{}
			}
		}
		for _, record := range stage.Records {
			finding := findings[record.Host]
			switch stage.Engine.Emits() {
			case enginediscovery.Observations:
				finding.Observations = append(finding.Observations, record.Fields)
			case enginediscovery.Endpoints:
				if port, ok := record.Fields["port"].(int); ok {
					finding.Ports = append(finding.Ports, port)
				}
				if ip, ok := record.Fields["ip"].(string); ok && ip != "" {
					finding.IP = ip
				}
			}
			findings[record.Host] = finding
		}
	}
	for host, finding := range findings {
		finding.Ports = distinctInts(finding.Ports)
		findings[host] = finding
	}
	return findings
}

func distinctInts(values []int) []int {
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]int, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func portsAsAny(values []int) []any {
	result := make([]any, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

func (r *Runner) merge(ctx context.Context, stages []Stage, at time.Time) (int, error) {
	findings := discoveryFindings(stages)
	if len(findings) == 0 {
		return 0, nil
	}
	hosts := make([]string, 0, len(findings))
	for host := range findings {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	timestamp := at.Format(time.RFC3339Nano)
	updated := 0
	var failures []error
	for _, host := range hosts {
		target, err := r.Store.EnsureDiscoveredTarget(ctx, host)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", host, err))
			continue
		}
		finding := findings[host]
		if len(finding.Ports) > 0 {
			target, err = observe.ApplyEndpoints(target, observe.EndpointObservation{
				Host: host, IP: finding.IP, Ports: finding.Ports,
			}, timestamp)
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", host, err))
				continue
			}
		}
		if record := observe.PrimaryRecord(finding.Observations); record != nil {
			projected := observe.InventoryProjection(record)
			if len(finding.Ports) > 0 {
				projected["open_ports"] = portsAsAny(finding.Ports)
			}
			if _, ok := projected["host_ip"]; !ok && finding.IP != "" {
				projected["host_ip"] = finding.IP
			}
			target, err = observe.Apply(target, projected, timestamp)
			if err != nil {
				failures = append(failures, fmt.Errorf("%s: %w", host, err))
				continue
			}
		}
		if err := r.Store.SaveTarget(ctx, target); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", host, err))
			continue
		}
		updated++
	}
	if len(failures) > 0 {
		return updated, fmt.Errorf("%d of %d observations could not be applied: %w",
			len(failures), len(hosts), failures[0])
	}
	return updated, nil
}
