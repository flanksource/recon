package api

import "strconv"

// The entity framework addresses every resource by an id and labels it with a
// name. These are the two together for each wire type: the id is what a URL
// path and a CLI argument carry, so it has to be the thing a person would
// actually type.

// GetID returns the host, which is the target's primary key.
func (t TargetDocument) GetID() string { return t.Host }

// GetName returns the host: there is nothing friendlier to show.
func (t TargetDocument) GetName() string { return t.Host }

// GetID returns the run's ulid.
func (s Scan) GetID() string { return s.ID }

// GetName returns the run's name, which is what the results file is called and
// what the runs list shows.
func (s Scan) GetName() string { return s.Name }

// GetID returns the sweep's ulid.
func (d Discover) GetID() string { return d.ID }

// GetName returns a label for the sweep: a sweep has no name of its own, so the
// chain and when it ran is the useful thing to show.
func (d Discover) GetName() string { return d.Chain + " " + d.RanAt }

// GetID returns kind/engine/name, which is the profile's composite key.
func (p Profile) GetID() string { return p.ID() }

// GetName returns the profile name on its own, which is what a profile is
// called everywhere except its address.
func (p Profile) GetName() string { return p.Name }

// FindingID addresses a finding within its run. A finding has no identity apart
// from where it appeared, so the run and the line it came from is the id.
func FindingID(scan string, line int) string {
	return scan + "#" + strconv.Itoa(line)
}

// GetID returns the finding's address within its run.
func (f Finding) GetID() string { return f.ScanID + "#" + strconv.Itoa(f.LineNo) }

// GetName returns the finding's template name, which is what the results list
// shows.
func (f Finding) GetName() string { return f.Name }

// EngineSpec is an engine as the API exposes it: the registry entry plus what
// is installed on this machine. Read-only — engines are compiled in, so there
// is nothing to create or edit.
type EngineSpec struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Title       string `json:"title"`
	Description string `json:"description"`
	DocsURL     string `json:"docsUrl,omitempty"`
	Binary      string `json:"binary"`

	// Accepts and Emits are empty for scan engines, which do not chain.
	Accepts string `json:"accepts,omitempty"`
	Emits   string `json:"emits,omitempty"`

	Version   string `json:"version,omitempty"`
	Installed bool   `json:"installed"`
	Managed   bool   `json:"managed"`
	Path      string `json:"path,omitempty"`
	Problem   string `json:"problem,omitempty"`

	// Sections is the option catalog the profile form renders. It is an opaque
	// ordered structure here because its order is meaningful.
	Sections any `json:"sections,omitempty"`

	// Defaults names the profile shipped with the engine.
	Defaults string `json:"defaults,omitempty"`
}

// GetID returns the engine's name.
func (e EngineSpec) GetID() string { return e.Name }

// GetName returns the engine's display title.
func (e EngineSpec) GetName() string { return e.Title }
