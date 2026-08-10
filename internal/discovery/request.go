package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

func modeFor(opts Options) (string, error) {
	if opts.Explicit || len(opts.Domains) > 0 || len(opts.CIDRs) > 0 {
		if len(opts.Hosts) == 0 && len(opts.Domains) == 0 && len(opts.CIDRs) == 0 {
			return "", fmt.Errorf("explicit discovery needs at least one host, domain or CIDR")
		}
		return ChainExplicit, nil
	}
	if len(opts.Hosts) > 0 {
		return ChainTargeted, nil
	}
	return ChainFull, nil
}

func requiredEngines(mode string, enumerates bool) []string {
	if mode == ChainFull || enumerates {
		return []string{"subfinder", "naabu", "httpx", "tlsx"}
	}
	return []string{"naabu", "httpx", "tlsx"}
}

func discoveryInput(opts Options) map[string]any {
	input := make(map[string]any, len(opts.Input)+3)
	for key, value := range opts.Input {
		input[key] = value
	}
	if len(opts.Hosts) > 0 && len(input) == 0 {
		input["hosts"] = distinctStrings(opts.Hosts)
	}
	if len(opts.Domains) > 0 {
		input["domains"] = distinctStrings(opts.Domains)
	}
	if len(opts.CIDRs) > 0 {
		input["cidrs"] = distinctStrings(opts.CIDRs)
	}
	return input
}

func runKey(opts Options) (string, error) {
	payload := struct {
		Profile  string
		Explicit bool
		Hosts    []string
		Domains  []string
		CIDRs    []string
		Input    map[string]any
	}{
		Profile: opts.Profile, Explicit: opts.Explicit,
		Hosts: distinctStrings(opts.Hosts), Domains: distinctStrings(opts.Domains),
		CIDRs: distinctStrings(opts.CIDRs), Input: opts.Input,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode discovery request: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func distinctStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
