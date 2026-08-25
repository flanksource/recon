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
	"regexp"

	"github.com/flanksource/deps/pkg/types"
)

// Subject is what a scan engine's input list holds.
//
// It lives on the Spec rather than the Engine interface because it is a fixed
// property of the engine, not a decision it makes per run — and putting it here
// means the existing engines need no new method and Spec.Validate can check it.
type Subject string

const (
	// SubjectEndpoints is the default: the host:port list the selector resolves
	// to. Everything that tests a service over the network wants this.
	SubjectEndpoints Subject = ""

	// SubjectAccounts is a list of cloud accounts. An engine that audits an
	// account's configuration through an API has no endpoint to contact, and
	// handing it one would misrepresent what it scanned.
	SubjectAccounts Subject = "accounts"

	// SubjectProviderContexts is a provider-defined account or organization
	// context resolved from the selected profile provider.
	SubjectProviderContexts Subject = "provider-contexts"
)

// ProvisioningMode says whether recon can install an engine or must use an
// executable maintained outside recon.
type ProvisioningMode string

const (
	ProvisioningManaged  ProvisioningMode = ""
	ProvisioningPathOnly ProvisioningMode = "path-only"
)

// Spec describes an engine: what it is, how to install it, and which options its
// profiles may set.
type Spec struct {
	// Name is the stable identifier used in profiles, runs and the API.
	Name string

	// Subject is what this engine's input list holds. Zero value is endpoints,
	// which is what every network scanner wants.
	Subject Subject

	// Binary is the executable name. Usually Name, but not always.
	Binary string

	Title       string
	Description string
	DocsURL     string

	// InProcess reports that the engine is linked into this binary rather than
	// spawned. Install, Binary and Version describe nothing for such an engine —
	// its version is whatever recon was compiled against — so they are neither
	// required nor consulted.
	InProcess bool

	// Install describes how to provision the binary. A deps.Package rather than
	// a shell line, so the version is pinned, the download is checksum-verified
	// and an already-installed copy on PATH is honoured.
	Install types.Package

	// ProvisioningPathOnly is for prerequisites whose upstream installation is
	// not representable as a checksum-verified deps package.
	Provisioning ProvisioningMode

	// InstallInstructions is the exact command shown when a PATH-only
	// prerequisite is missing, and recommended when its version differs.
	InstallInstructions string

	// Version is the constraint deps resolves. Recording the resolved version on
	// each run is what makes a run reproducible.
	Version string

	// Options contains the complete profile schemas this engine accepts. A
	// provider-backed engine selects one variant through its discriminator.
	Options OptionCatalog

	// Defaults is the profile created for this engine on a blank database. With
	// no import step, this is where a working configuration comes from.
	Defaults DefaultProfile

	// Profiles are additional built-in profiles seeded without overwriting
	// user-edited or user-created profiles.
	Profiles []DefaultProfile

	// ValidateOptions applies engine-specific constraints that the field catalog
	// cannot express, such as mutually exclusive flags.
	ValidateOptions func(map[string]any) error

	// ValidateProviderCredentials applies authentication-method constraints and
	// returns any stored connection references that must be type-checked.
	ValidateProviderCredentials func(config, context, credentials map[string]any) ([]CredentialConnection, error)
}

type CredentialConnection struct {
	Reference string
	Type      string
}

// DefaultProfile is the profile seeded for an engine when none exists.
type DefaultProfile struct {
	Name    string
	Comment string
	Config  map[string]any
	Paths   []string
}

// BuiltInProfiles returns the profiles seeded for an engine on startup.
func (s Spec) BuiltInProfiles() []DefaultProfile {
	profiles := make([]DefaultProfile, 0, 1+len(s.Profiles))
	profiles = append(profiles, s.Defaults)
	return append(profiles, s.Profiles...)
}

// ValidateConfig checks both the option catalog and engine-specific constraints.
func (s Spec) ValidateConfig(config map[string]any) error {
	if err := s.Options.ValidateConfig(config); err != nil {
		return err
	}
	if s.ValidateOptions != nil {
		return s.ValidateOptions(config)
	}
	return nil
}

// ValidateContext checks provider-owned target context against the same option
// variant selected by the profile.
func (s Spec) ValidateContext(config, context map[string]any) error {
	return s.Options.ValidateContext(config, context)
}

// ValidateOverrides ensures run-only changes cannot switch the option variant
// selected by the stored profile.
func (s Spec) ValidateOverrides(config, overrides map[string]any) error {
	return s.Options.ValidateOverrides(config, overrides)
}

// Validate checks a spec at registration time. These are programming errors: a
// malformed spec should fail the process, not a scan.
func (s Spec) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("engine spec: name is required")
	}

	switch s.Subject {
	case SubjectEndpoints, SubjectAccounts, SubjectProviderContexts:
	default:
		return fmt.Errorf("engine %s: unknown subject %q", s.Name, s.Subject)
	}

	// A linked-in engine has nothing to provision, so the binary contract does
	// not apply to it. Everything below it still does: the option catalog and
	// the built-in profiles are what a profile is validated against, and those
	// are the same either way.
	if s.InProcess && s.Provisioning != ProvisioningManaged {
		return fmt.Errorf("engine %s: in-process engine cannot use %q provisioning", s.Name, s.Provisioning)
	}
	if !s.InProcess {
		if s.Binary == "" {
			return fmt.Errorf("engine %s: binary is required", s.Name)
		}
		if s.Install.VersionCommand == "" {
			return fmt.Errorf("engine %s: install version_command is required", s.Name)
		}
		if s.Install.VersionRegex != "" {
			compiled, err := regexp.Compile(s.Install.VersionRegex)
			if err != nil {
				return fmt.Errorf("engine %s: install version_regex: %w", s.Name, err)
			}
			if compiled.NumSubexp() == 0 {
				return fmt.Errorf("engine %s: install version_regex must capture the version", s.Name)
			}
		}

		switch s.Provisioning {
		case ProvisioningManaged:
			if s.Install.Name == "" {
				return fmt.Errorf("engine %s: install package is required", s.Name)
			}
			if s.Install.Manager == "" {
				return fmt.Errorf("engine %s: install manager is required", s.Name)
			}
		case ProvisioningPathOnly:
			if s.Version == "" {
				return fmt.Errorf("engine %s: version is required for PATH-only provisioning", s.Name)
			}
			if s.Install.Name != "" || s.Install.Manager != "" {
				return fmt.Errorf("engine %s: PATH-only provisioning cannot declare a deps package", s.Name)
			}
			if s.InstallInstructions == "" {
				return fmt.Errorf("engine %s: install instructions are required for PATH-only provisioning", s.Name)
			}
		default:
			return fmt.Errorf("engine %s: unknown provisioning mode %q", s.Name, s.Provisioning)
		}
	}

	if err := s.Options.Validate(); err != nil {
		return fmt.Errorf("engine %s: %w", s.Name, err)
	}

	names := map[string]bool{}
	for _, profile := range s.BuiltInProfiles() {
		if profile.Name == "" {
			return fmt.Errorf("engine %s: built-in profile name is required", s.Name)
		}
		if names[profile.Name] {
			return fmt.Errorf("engine %s: duplicate built-in profile %q", s.Name, profile.Name)
		}
		names[profile.Name] = true
		if err := s.ValidateConfig(profile.Config); err != nil {
			return fmt.Errorf("engine %s: built-in profile %q: %w", s.Name, profile.Name, err)
		}
	}
	return nil
}
