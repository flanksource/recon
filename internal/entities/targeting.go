package entities

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/flanksource/recon/internal/store"
)

// runTarget is the common targeting surface for scan and discovery. Inventory
// selectors and explicit discovery inputs are different modes and cannot be
// combined in one run.
type runTarget struct {
	Selector string   `flag:"selector" help:"Kubernetes label selector over target tags"`
	Class    []string `flag:"class" help:"Only inventory targets in these classes"`
	Tags     []string `flag:"tags" help:"Only inventory targets carrying any of these tags"`
	Profiles []string `flag:"profiles" help:"Only inventory targets assigned these scan profiles"`
	Ports    []int    `flag:"ports" help:"Only inventory targets with these ports"`
	Status   []int    `flag:"status" help:"Only inventory targets with these HTTP status codes"`
	LastSeen string   `flag:"last-seen" help:"Only inventory targets seen since this RFC3339 time or duration"`
	Live     bool     `flag:"live" help:"Only inventory targets that last answered over HTTP"`

	Host   []string `flag:"host" help:"Discover or scan this hostname or IP; repeatable"`
	Domain []string `flag:"domain" help:"Enumerate this DNS domain; repeatable"`
	CIDR   []string `flag:"cidr" help:"Discover this IP network in CIDR notation; repeatable"`
}

type resolvedTarget struct {
	Inventory store.TargetOpts
	Hosts     []string
	Domains   []string
	CIDRs     []string
}

func (t resolvedTarget) explicit() bool {
	return len(t.Hosts) > 0 || len(t.Domains) > 0 || len(t.CIDRs) > 0
}

func (t runTarget) resolve() (resolvedTarget, error) {
	resolved := resolvedTarget{
		Inventory: store.TargetOpts{
			Selector: t.Selector,
			Class:    t.Class, Tags: t.Tags, Profiles: t.Profiles, Ports: t.Ports,
			Status: t.Status, LastSeen: t.LastSeen, Live: t.Live,
		},
		Hosts: uniqueStrings(t.Host), Domains: uniqueStrings(t.Domain),
	}

	for _, value := range uniqueStrings(t.CIDR) {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return resolvedTarget{}, fmt.Errorf("invalid CIDR %q: %w", value, err)
		}
		resolved.CIDRs = append(resolved.CIDRs, prefix.Masked().String())
	}

	if resolved.explicit() && !resolved.Inventory.Empty() {
		return resolvedTarget{}, fmt.Errorf("cannot combine --selector or inventory filters with --host, --domain or --cidr")
	}
	if err := resolved.Inventory.Validate(); err != nil {
		return resolvedTarget{}, err
	}
	return resolved, nil
}

func uniqueStrings(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			unique[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
