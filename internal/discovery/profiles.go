package discovery

import (
	"fmt"
	"sort"
	"strings"

	enginediscovery "github.com/flanksource/recon/internal/engines/discovery"
)

// DefaultProfile is the profile name every engine falls back to.
const DefaultProfile = "default"

// ProfileSet is the stored configuration a sweep runs each of its engines with.
//
// A sweep is not one profile: it drives several engines, and each of them has
// its own profile keyed discovery:<engine>:<name>. A run therefore carries a
// base name every engine uses plus per-engine overrides, so one sweep can probe
// aggressively with naabu while leaving httpx alone.
type ProfileSet struct {
	// Base is the name used by any engine without an override.
	Base string

	// Overrides names the profile for one engine, keyed by engine name.
	Overrides map[string]string
}

// ParseProfiles reads the profile references a caller supplied.
//
// A bare name is the base; `engine=name` overrides a single engine. Ambiguity
// is rejected rather than resolved by precedence: two bases or two overrides for
// the same engine mean the caller believes something the run cannot honour.
func ParseProfiles(refs []string) (ProfileSet, error) {
	set := ProfileSet{Overrides: map[string]string{}}
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}

		engine, name, qualified := strings.Cut(ref, "=")
		engine, name = strings.TrimSpace(engine), strings.TrimSpace(name)
		if !qualified {
			if set.Base != "" && set.Base != engine {
				return ProfileSet{}, fmt.Errorf(
					"discovery profiles %q: %q and %q both apply to every engine; qualify one as engine=name",
					strings.Join(refs, ","), set.Base, engine)
			}
			set.Base = engine
			continue
		}
		if name == "" {
			return ProfileSet{}, fmt.Errorf("discovery profile %q names no profile for %s", ref, engine)
		}
		if _, err := enginediscovery.Get(engine); err != nil {
			return ProfileSet{}, fmt.Errorf("discovery profile %q: %w", ref, err)
		}
		if existing, ok := set.Overrides[engine]; ok && existing != name {
			return ProfileSet{}, fmt.Errorf(
				"discovery profiles %q: %s is assigned both %q and %q",
				strings.Join(refs, ","), engine, existing, name)
		}
		set.Overrides[engine] = name
	}
	if set.Base == "" {
		set.Base = DefaultProfile
	}
	return set, nil
}

// For returns the profile name an engine runs with.
func (s ProfileSet) For(engine string) string {
	if name, ok := s.Overrides[engine]; ok {
		return name
	}
	if s.Base == "" {
		return DefaultProfile
	}
	return s.Base
}

// Resolve names the profile each engine in a chain runs with.
func (s ProfileSet) Resolve(engines []string) map[string]string {
	resolved := make(map[string]string, len(engines))
	for _, engine := range engines {
		resolved[engine] = s.For(engine)
	}
	return resolved
}

// Refs renders the set back to the reference list it was parsed from, in a
// canonical order so two spellings of the same request hash alike.
func (s ProfileSet) Refs() []string {
	base := s.Base
	if base == "" {
		base = DefaultProfile
	}
	refs := []string{base}
	for engine, name := range s.Overrides {
		refs = append(refs, engine+"="+name)
	}
	sort.Strings(refs[1:])
	return refs
}

// String describes the set for a task label.
func (s ProfileSet) String() string { return strings.Join(s.Refs(), ",") }
