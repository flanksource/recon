package api

// The entity framework addresses every resource by an id and labels it with a
// name. These are the two together for each wire type: the id is what a URL
// path and a CLI argument carry, so it has to be the thing a person would
// actually type.

// GetID returns the stable inventory identity. Directly constructed legacy host
// values resolve to their address so observation code can build one before it
// reaches the store.
func (t TargetDocument) GetID() string {
	if t.ID != "" {
		return t.ID
	}
	return t.Host
}

// GetName returns the address for a host and the stable name for a provider
// context, which has no network address.
func (t TargetDocument) GetName() string {
	if t.Host != "" {
		return t.Host
	}
	return t.ID
}

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

// GetID returns the finding row's stable database identity.
func (f Finding) GetID() string { return f.ID }

// GetName returns the check.s title, which is what the results list shows.
func (f Finding) GetName() string {
	if f.FindingInfo == nil {
		return f.CheckID
	}
	return f.FindingInfo.Title
}

// GetID returns the resource's ulid, falling back to its natural key for one an
// engine has built but the store has not yet recorded — the same shape as
// TargetDocument falling back to its host.
func (r Resource) GetID() string {
	if r.ID != "" {
		return r.ID
	}
	return r.Key().String()
}

// GetName returns what a person recognises the resource as. The uid is a last
// resort rather than the default: a GCP firewall's uid is 1429543158501771126
// and its name is tailscale-router, and only one of those is worth a column.
func (r Resource) GetName() string {
	if r.Name != "" {
		return r.Name
	}
	return r.UID
}

// GetID returns the rule's name, which is what mutes.json cites and what a
// person types.
func (m MuteRule) GetID() string { return m.Name }

// GetName returns the rule's name.
func (m MuteRule) GetName() string { return m.Name }

// Zone is a DNS zone discovery enumerates. Zones are configured rather than
// discovered — they are what a sweep starts from, so there is nothing to infer
// them from.
type Zone struct {
	Zone string `json:"zone"`
}

// GetID returns the zone name.
func (z Zone) GetID() string { return z.Zone }

// GetName returns the zone name.
func (z Zone) GetName() string { return z.Zone }

// The two engine kinds. They are separate registries with separate profile
// namespaces because they answer different questions: discovery updates the
// inventory, a scan reports findings against it.
const (
	KindDiscovery = "discovery"
	KindScan      = "scan"
)

// Kinds lists both, in the order a sweep and then a scan happen.
func Kinds() []string { return []string{KindDiscovery, KindScan} }

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

	// Subject is what this engine's input list holds — an address, or a
	// provider-native scope. Absent means endpoints. It is what tells a caller
	// which targets an engine's profiles can be assigned to at all: a profile
	// that audits a cloud account means nothing against a hostname.
	Subject string `json:"subject,omitempty"`

	// Accepts and Emits are empty for scan engines, which do not chain.
	Accepts string `json:"accepts,omitempty"`
	Emits   string `json:"emits,omitempty"`

	// Default reports whether a sweep runs this engine when the caller chooses
	// none, which is what the engine picker opens on. False for scan engines,
	// which are chosen one at a time rather than as a set.
	Default bool `json:"default,omitempty"`

	Version   string `json:"version,omitempty"`
	Installed bool   `json:"installed"`
	Managed   bool   `json:"managed"`
	Path      string `json:"path,omitempty"`
	Problem   string `json:"problem,omitempty"`

	// Templates is the corpus an engine matches against, when it has one. For an
	// engine compiled into this binary the binary cannot be missing, so this is
	// the artifact that can actually be absent or stale — and without it every
	// scan matches nothing, which reads as a clean run rather than a broken
	// install. Nil for engines that carry no catalogue.
	Templates *EngineTemplates `json:"templates,omitempty"`

	// Options contains the typed profile schemas the profile form renders.
	Options EngineOptions `json:"options"`

	// Defaults names the profile shipped with the engine.
	Defaults string `json:"defaults,omitempty"`
}

// EngineOptions is the provider-aware option catalog exposed by an engine.
type EngineOptions struct {
	Discriminator string                `json:"discriminator,omitempty"`
	Variants      []EngineOptionVariant `json:"variants"`
}

// EngineOptionVariant contains inline schemas for runtime consumers and
// component references for generated API documentation.
type EngineOptionVariant struct {
	ID                    string      `json:"id"`
	Title                 string      `json:"title"`
	Schema                JSONSchema  `json:"schema"`
	ContextSchema         *JSONSchema `json:"contextSchema,omitempty"`
	CredentialSchema      *JSONSchema `json:"credentialSchema,omitempty"`
	SchemaRef             string      `json:"schemaRef,omitempty"`
	ContextSchemaRef      string      `json:"contextSchemaRef,omitempty"`
	CredentialSchemaRef   string      `json:"credentialSchemaRef,omitempty"`
	CLIArgumentsSchemaRef string      `json:"cliArgumentsSchemaRef,omitempty"`
}

// JSONSchema is a Draft 2020-12 schema document carried as API data.
type JSONSchema map[string]any

// JSONSchema describes schema documents to Clicky's OpenAPI reflector without
// pretending that every engine/provider has one static property shape.
func (JSONSchema) JSONSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"description":          "Draft 2020-12 JSON Schema document",
		"additionalProperties": true,
	}
}

// EngineTemplates describes an installed template corpus.
type EngineTemplates struct {
	Version      string `json:"version,omitempty"`
	Count        int    `json:"count"`
	Path         string `json:"path,omitempty"`
	ItemLabel    string `json:"itemLabel,omitempty"`
	ProfileLabel string `json:"profileLabel,omitempty"`
	// Problem says why the corpus could not be read, rather than reporting a
	// count of zero as if the engine simply had nothing to run.
	Problem string `json:"problem,omitempty"`
}

// GetID returns the engine's name.
func (e EngineSpec) GetID() string { return e.Name }

// GetName returns the engine's display title.
func (e EngineSpec) GetName() string { return e.Title }
