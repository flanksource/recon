// Package engines holds what discovery and scan engines have in common: how
// they are described, how their binary is provisioned, and how one run is
// parameterised.
//
// The two kinds are deliberately separate registries rather than one with a
// `kind` field. They have different contracts — a discovery engine emits
// observations that update the inventory and chains into the next stage, while a
// scan engine emits findings against a fixed endpoint list and carries the risk
// gating. Sharing an interface would mean every implementation returning nil for
// half of it.
package engines

import (
	"fmt"

	"github.com/flanksource/deps/pkg/types"
)

// Spec describes an engine: what it is, how to install it, and which options its
// profiles may set.
type Spec struct {
	// Name is the stable identifier used in profiles, runs and the API.
	Name string

	// Binary is the executable name. Usually Name, but not always.
	Binary string

	Title       string
	Description string
	DocsURL     string

	// Install describes how to provision the binary. A deps.Package rather than
	// a shell line, so the version is pinned, the download is checksum-verified
	// and an already-installed copy on PATH is honoured.
	Install types.Package

	// Version is the constraint deps resolves. Recording the resolved version on
	// each run is what makes a run reproducible.
	Version string

	// Sections is the ordered option catalog. Order is meaningful: it groups the
	// options into the form the UI renders, so it is a slice rather than a map.
	Sections Sections

	// Defaults is the profile created for this engine on a blank database. With
	// no import step, this is where a working configuration comes from.
	Defaults DefaultProfile

	// ValidateOptions applies engine-specific constraints that the field catalog
	// cannot express, such as mutually exclusive flags.
	ValidateOptions func(map[string]any) error
}

// DefaultProfile is the profile seeded for an engine when none exists.
type DefaultProfile struct {
	Name    string
	Comment string
	Config  map[string]any
	Paths   []string
}

// ValidateConfig checks both the option catalog and engine-specific constraints.
func (s Spec) ValidateConfig(config map[string]any) error {
	if err := s.Sections.Validate(config); err != nil {
		return err
	}
	if s.ValidateOptions != nil {
		return s.ValidateOptions(config)
	}
	return nil
}

// Validate checks a spec at registration time. These are programming errors: a
// malformed spec should fail the process, not a scan.
func (s Spec) Validate() error {
	switch {
	case s.Name == "":
		return fmt.Errorf("engine spec: name is required")
	case s.Binary == "":
		return fmt.Errorf("engine %s: binary is required", s.Name)
	case s.Install.Name == "":
		return fmt.Errorf("engine %s: install package is required", s.Name)
	case s.Install.Manager == "":
		return fmt.Errorf("engine %s: install manager is required", s.Name)
	}

	// Without a version command, `doctor` cannot tell an outdated binary from a
	// current one, and the run cannot record what it actually used.
	if s.Install.VersionCommand == "" {
		return fmt.Errorf("engine %s: install version_command is required", s.Name)
	}

	if s.Defaults.Name != "" {
		if err := s.ValidateConfig(s.Defaults.Config); err != nil {
			return fmt.Errorf("engine %s: default profile %q: %w", s.Name, s.Defaults.Name, err)
		}
	}
	return nil
}
