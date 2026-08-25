package api

import (
	"fmt"
	"strings"
)

// ResourceKind says what sort of thing a resource is, which is a different
// question from its provider type.
const (
	// KindAccount is the account, project or subscription itself. Prowler
	// synthesises a resource for it whenever a check has nothing more specific
	// to point at, typing it with whichever service the check belongs to — so
	// one project arrives typed four different ways in a single run, and
	// recognising the case is what keeps it one row instead of four.
	KindAccount = "account"
	// KindCloudResource is a thing inside an account: a bucket, a firewall rule.
	KindCloudResource = "cloud-resource"
	// KindArtifact is something scanned rather than owned — a container image, a
	// filesystem, a repository.
	KindArtifact = "artifact"
	// KindEndpoint is a network address a scanner reached.
	KindEndpoint = "endpoint"
)

// ResourceState says whether a run entitled to look still sees it.
const (
	ResourcePresent = "present"
	ResourceAbsent  = "absent"
)

// What is currently true about one check on one resource.
const (
	// StatusOpen is a check that failed the last time it ran.
	StatusOpen = "open"
	// StatusResolved is a check that no longer fails. Reason says how recon
	// knows, which is not the same claim in both cases — see FindingState.
	StatusResolved = "resolved"
	// StatusMuted is a check a rule accepts. It is recorded rather than silent
	// so a muted problem is visibly muted instead of looking like a clean one.
	StatusMuted = "muted"
	// StatusManual is a check whose verdict is a human's to make.
	StatusManual = "manual"
)

// How a check stopped being open.
const (
	// ReasonPassed is the only resolution that is a fact rather than an
	// inference: the check ran again against the same resource and passed.
	ReasonPassed = "passed"
	// ReasonResourceAbsent is a resource a covering run no longer sees.
	ReasonResourceAbsent = "resource-absent"
	// ReasonNotReported is a resource still seen whose check said nothing about
	// it, which usually means the check no longer applies.
	ReasonNotReported = "not-reported"
	// ReasonSuppressed is the provider itself declining to judge.
	ReasonSuppressed = "provider-suppressed"
)

// PageInfo is the window a listing answered with.
type PageInfo struct {
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
	Total  int64 `json:"total"`
}

// ResourcePage is a page of resources and the total behind it.
//
// Resources are the one listing that pages. Targets are curated by hand and
// bounded by human effort; resources are enumerated by a machine and bounded by
// nothing, and the tab is opened cold with no filter — where "the first 500 of
// many" is not a partial answer to "what have I got" but a wrong one.
type ResourcePage struct {
	Data []Resource `json:"data"`
	Page PageInfo   `json:"page"`
}

// ResourceKey identifies a resource before the store has assigned it an id.
//
// Three parts, because a provider uid is not unique on its own: `default` is a
// VPC in every GCP project and keying on the uid alone would merge them. Scope
// is the account rather than the inventory target — one target covers several
// accounts and one account can be reached by two targets, so keying on the
// target would split one real resource into a row per way of reaching it.
type ResourceKey struct {
	Provider string `json:"provider"`
	Scope    string `json:"scope,omitempty"`
	UID      string `json:"uid"`
}

func (k ResourceKey) String() string { return k.Provider + "/" + k.Scope + "/" + k.UID }

func (k ResourceKey) Validate() error {
	switch {
	case k.Provider == "":
		return fmt.Errorf("resource provider is required")
	case k.UID == "":
		return fmt.Errorf("resource uid is required")
	default:
		return nil
	}
}

// ParseResourceKey reads the provider/scope/uid form.
//
// It cuts on the first two separators only, because a uid contains them: a GCP
// service account's is `projects/X/serviceAccounts/Y`, and splitting on every
// slash would leave the key naming a project.
func ParseResourceKey(value string) (ResourceKey, error) {
	provider, rest, ok := strings.Cut(value, "/")
	if !ok {
		return ResourceKey{}, fmt.Errorf("invalid resource key %q: expected provider/scope/uid", value)
	}
	scope, uid, ok := strings.Cut(rest, "/")
	if !ok {
		return ResourceKey{}, fmt.Errorf("invalid resource key %q: expected provider/scope/uid", value)
	}
	key := ResourceKey{Provider: provider, Scope: scope, UID: uid}
	if err := key.Validate(); err != nil {
		return ResourceKey{}, fmt.Errorf("invalid resource key %q: %w", value, err)
	}
	return key, nil
}

// Resource is one thing a scan examined, whatever the verdict.
//
// Passed and Suppressed describe what an engine reported about it rather than
// what it is. They are carried here so a run reports one resource per subject
// instead of one per check, and they are what lets a later run resolve a
// finding: a pass says the check ran and the problem is gone, which silence
// never says.
type Resource struct {
	ID       string `json:"id,omitempty"`
	Provider string `json:"provider"`
	Scope    string `json:"scope,omitempty"`
	UID      string `json:"uid"`

	Kind    string `json:"kind"`
	Type    string `json:"type,omitempty"`
	Name    string `json:"name,omitempty"`
	Service string `json:"service,omitempty"`
	Region  string `json:"region,omitempty"`

	TargetID    string `json:"targetId,omitempty"`
	AccountName string `json:"accountName,omitempty"`
	OrgUID      string `json:"orgUid,omitempty"`
	OrgName     string `json:"orgName,omitempty"`
	// Engines is read-side only: which engines have described this resource. An
	// engine reporting one does not set it — the run it belongs to already says
	// which engine that is, and one row can be described by several.
	Engines StringList `json:"engines,omitempty"`

	// ConfigType and ExternalIDs are what Mission Control's catalog would know
	// the same thing as, empty wherever recon cannot say.
	ConfigType  string     `json:"configType,omitempty"`
	ExternalIDs StringList `json:"externalIds,omitempty"`

	Tags     StringList        `json:"tags"`
	Labels   map[string]string `json:"labels,omitempty"`
	Metadata map[string]any    `json:"metadata,omitempty"`

	State     string `json:"state,omitempty"`
	FirstSeen string `json:"firstSeen,omitempty"`
	LastSeen  string `json:"lastSeen,omitempty"`
	ScanID    string `json:"scanId,omitempty"`

	// Passed and Suppressed name the checks that reported a verdict against this
	// resource in this run. Written by an engine, never read back from storage.
	Passed     StringList `json:"passed,omitempty"`
	Suppressed StringList `json:"suppressed,omitempty"`

	// Findings and Severities are the read side: what is open against it now.
	Findings   int            `json:"findings"`
	Severities map[string]int `json:"severities,omitempty"`
}

func (r Resource) Key() ResourceKey {
	return ResourceKey{Provider: r.Provider, Scope: r.Scope, UID: r.UID}
}

// Ref projects a resource onto the reference a finding carries.
func (r Resource) Ref() ResourceRef {
	return ResourceRef{
		ID: r.ID, Provider: r.Provider, Scope: r.Scope, UID: r.UID, Name: r.Name,
		Type: r.Type, Service: r.Service, Region: r.Region,
	}
}

// ResourceRef names one thing a finding is about.
//
// It is deliberately thinner than the resource itself: a finding carries a
// reference so the UI can render and link it, while the provider's own document
// and the finding counts live on the resource row. Keeping the two apart is what
// stops every finding in findings.jsonl carrying a copy of a 95KB metadata blob.
type ResourceRef struct {
	// ID is the recon resource this reference resolved to, empty until one has
	// been recorded for it.
	ID string `json:"id,omitempty"`
	// Provider, Scope and UID are the resource's canonical natural key. They
	// travel together so persistence never has to guess identity from Host or
	// MatchedAt, which are evidence locations rather than resources.
	Provider string `json:"provider,omitempty"`
	Scope    string `json:"scope,omitempty"`

	// UID is the provider's own identifier, which is frequently not
	// human-readable: a GCP firewall's uid is an opaque number and its name is
	// what an operator recognises.
	UID  string `json:"uid"`
	Name string `json:"name,omitempty"`

	// Type is the provider's own resource type — for GCP the Cloud Asset
	// Inventory asset type, e.g. compute.googleapis.com/Firewall.
	Type    string `json:"type,omitempty"`
	Service string `json:"service,omitempty"`
	Region  string `json:"region,omitempty"`
}

// Empty reports a reference that names nothing.
func (r ResourceRef) Empty() bool { return r.UID == "" && r.Name == "" }

// Display is what to show for a resource: its name where it has one, and its
// uid otherwise. A uid is the fallback rather than the default because half of
// them are opaque numbers.
func (r ResourceRef) Display() string {
	if r.Name != "" {
		return r.Name
	}
	return r.UID
}

// ResourceFallback is the reference synthesised for a finding whose engine names
// no resource of its own.
//
// Host is the identity and MatchedAt the label, which is the wrong way round
// only if you read the field names rather than the values: for trivy Host is the
// scanned artifact and MatchedAt is `Dockerfile:2` within it, and for nuclei Host
// is the target and MatchedAt the URL that answered. It reproduces, field for
// field, what every consumer used to reconstruct by hand.
func (f Finding) ResourceFallback() ResourceRef {
	name := f.MatchedAt
	if name == "" {
		name = f.Host
	}
	return ResourceRef{UID: f.Host, Name: name, Type: f.Engine}
}

