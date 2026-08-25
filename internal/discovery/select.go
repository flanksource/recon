package discovery

import (
	"fmt"
	"sort"
	"strings"

	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
)

// kindRank is where a stage sits in a sweep, by what it consumes.
//
// A chain is an ordered pipeline, but a caller choosing engines is choosing a
// set — a list of checkboxes has no order to offer. The order therefore comes
// from the kinds, which already form a fixed progression: zones name hosts,
// hosts have endpoints, endpoints answer over HTTP. Chain.Validate still has the
// last word; this only saves the caller from having to know the order.
var kindRank = map[enginediscovery.Kind]int{
	enginediscovery.Zones:     0,
	enginediscovery.Hosts:     1,
	enginediscovery.Origins:   2,
	enginediscovery.Endpoints: 3,
}

// DefaultEngines names the engines a sweep runs when the caller chooses none.
//
// It is the set a full sweep drives — a targeted sweep drops the stage that
// enumerates a zone, because its seed is hosts and Chain.Validate is what says
// so. Exported because the picker has to show what is already on before anyone
// touches it, and a second list in the UI would drift from this one.
func DefaultEngines() []string { return requiredEngines(ChainFull, false) }

// OrderEngines puts a chosen set of discovery engines into pipeline order,
// dropping blanks and duplicates. Engines that consume the same kind keep a
// stable order by name, so one selection always produces one chain.
func OrderEngines(names []string) ([]string, error) {
	ranks := make(map[string]int, len(names))
	ordered := make([]string, 0, len(names))

	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || contains(ordered, name) {
			continue
		}
		engine, err := enginediscovery.Get(name)
		if err != nil {
			return nil, err
		}
		rank, known := kindRank[engine.Accepts()]
		if !known {
			return nil, fmt.Errorf("discovery engine %s consumes %s, which no sweep can supply",
				name, engine.Accepts())
		}
		ranks[name] = rank
		ordered = append(ordered, name)
	}

	sort.SliceStable(ordered, func(i, j int) bool {
		if ranks[ordered[i]] != ranks[ordered[j]] {
			return ranks[ordered[i]] < ranks[ordered[j]]
		}
		return ordered[i] < ordered[j]
	})
	return ordered, nil
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}
	return false
}

// seedsFromZones splits a selection into the stages that enumerate a zone and
// the stages that probe what those produced. An explicit sweep runs them as two
// chains — the caller may supply domains, hosts and CIDRs in one request — so
// the split has to happen before either chain is built.
func seedsFromZones(names []string) (enumerate, probe []string) {
	for _, name := range names {
		engine, err := enginediscovery.Get(name)
		if err != nil {
			// OrderEngines already rejected unknown names; anything reaching
			// here is a known engine.
			continue
		}
		if engine.Accepts() == enginediscovery.Zones {
			enumerate = append(enumerate, name)
			continue
		}
		probe = append(probe, name)
	}
	return enumerate, probe
}

