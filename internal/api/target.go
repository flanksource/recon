// Package api holds the wire types. They mirror what the TypeScript backend
// emitted, field for field, and are asserted against contract/golden/. Nothing
// here may import gorm or the store: a persistence tag must never leak into a
// response body.
package api

import "encoding/json"

// TargetSchemaRef and TargetVersion are stamped onto every document on read and
// are never stored. The TypeScript store wrote them into each file; keeping them
// on the wire is what lets the golden documents compare equal.
const (
	TargetSchemaRef = "../target.schema.json"
	TargetVersion   = 3
)

// TargetKind is what a target addresses.
//
// It is separate from Class because the two answer different questions: Class
// is how exposed a target is, TargetKind is what kind of thing it is — a cloud
// context can be production or a sandbox exactly as a host can. Spelled out in
// full because Kind already names the two engine registries.
type TargetKind string

const (
	// KindHost is something on the network with an address and ports. Every
	// discovery engine and every endpoint-driven scan works on these.
	KindHost TargetKind = "host"

	// KindProviderContext is one explicitly configured scope for a provider
	// scanner. It may cover an account, project, organization, repository or
	// another provider-native scope; the generated provider argument schema owns
	// that shape rather than recon growing one target kind per provider.
	KindProviderContext TargetKind = "provider-context"
)

// kindTraits is one entry in the kind vocabulary: what a target of this kind
// is, and what can be done to it.
type kindTraits struct {
	Name TargetKind

	// Addressable targets are reachable over the network, so they resolve to
	// endpoints and discovery, probes and endpoint-driven scans see them.
	Addressable bool

	// ProviderContext targets are consumed by a provider scanner rather than
	// resolved to a network endpoint.
	ProviderContext bool
}

// kindTable is the vocabulary, in schema order.
//
// One table rather than a predicate each: between them the questions have three
// answers, and deriving "a scan can audit it" from "it has no address" is
// exactly how an organization ends up in front of an engine that wants a
// project id.
var kindTable = []kindTraits{
	{Name: KindHost, Addressable: true},
	{Name: KindProviderContext, ProviderContext: true},
}

// TargetKinds lists every valid kind in schema order.
func TargetKinds() []TargetKind {
	names := make([]TargetKind, 0, len(kindTable))
	for _, entry := range kindTable {
		names = append(names, entry.Name)
	}
	return names
}

// traits resolves the vocabulary entry, normalising through String so the
// absent-means-host default lives in exactly one place. An unknown kind gets
// the zero entry: neither addressable nor auditable, which is the safe reading
// of a value nothing here recognises.
func (k TargetKind) traits() kindTraits {
	name := TargetKind(k.String())
	for _, entry := range kindTable {
		if entry.Name == name {
			return entry
		}
	}
	return kindTraits{}
}

// Addressable reports whether a target of this kind can be reached over the
// network — which is what decides whether it resolves to endpoints, and so
// whether discovery, probes and endpoint-driven scans see it at all.
func (k TargetKind) Addressable() bool { return k.traits().Addressable }

// ProviderContext reports whether the target is a provider-native execution
// scope rather than a network address.
func (k TargetKind) ProviderContext() bool { return k.traits().ProviderContext }

// String renders the kind, resolving the absent-means-host default so callers
// storing or displaying it never have to.
func (k TargetKind) String() string {
	if k == "" {
		return string(KindHost)
	}
	return string(k)
}

// Class is the curated classification that decides whether a target is in scope
// for a scan and whether an intrusive scan needs confirmation.
type Class string

const (
	ClassPublic       Class = "public"
	ClassProd         Class = "prod"
	ClassNonProd      Class = "non-prod"
	ClassInternal     Class = "internal"
	ClassUnclassified Class = "unclassified"
	ClassDeactivated  Class = "deactivated"
)

// Classes lists every valid class in schema order.
func Classes() []Class {
	return []Class{ClassPublic, ClassProd, ClassNonProd, ClassInternal, ClassUnclassified, ClassDeactivated}
}

// Risky reports whether scanning this class with an intrusive profile requires
// explicit confirmation. An unknown class — a host absent from the inventory —
// is risky, which is why the caller passes "" for one.
func (c Class) Risky() bool {
	return c == ClassProd || c == ClassPublic || c == ClassUnclassified || c == ""
}

// TargetDocument is one inventory target as the API returns it.
//
// Pointer fields are not decoration. The schema gives http.title, every tls
// string and the cpe product/vendor no minLength, and the observation
// normalizer deliberately preserves an empty string there while dropping every
// other empty value. A plain string with omitempty would silently turn a real
// "" into an absent key. Curated strings do carry minLength: 1, so they are
// plain strings.
//
// Profiles and Tags are required arrays and must serialize as [] rather than
// null, which a nil Go slice would produce.
type TargetDocument struct {
	Schema  string `json:"$schema"`
	Version int    `json:"version"`
	// ID is the stable inventory identity. It is independent of a host address
	// and of the provider resources one context happens to cover.
	ID   string `json:"id"`
	Host string `json:"host,omitempty"`

	// Kind is omitempty because host is the schema default.
	Kind     TargetKind `json:"kind,omitempty"`
	Provider string     `json:"provider,omitempty"`
	// CredentialMode makes ambient credential use an explicit choice. Arguments
	// contains provider-native non-secret selectors and paths; provider schemas
	// reject direct credential values before they are stored.
	CredentialMode CredentialMode       `json:"credentialMode,omitempty"`
	Arguments      map[string]any       `json:"arguments,omitempty"`
	Credentials    *ProviderCredentials `json:"credentials,omitempty"`
	Class          Class                `json:"class"`
	App            string               `json:"app,omitempty"`
	Cluster        string               `json:"cluster,omitempty"`
	Source         string               `json:"source,omitempty"`
	Profiles       []string             `json:"profiles"`
	Ports          []int                `json:"ports,omitempty"`
	Tags           []string             `json:"tags"`
	Notes          string               `json:"notes,omitempty"`
	Reason         string               `json:"reason,omitempty"`

	Observed *Observed  `json:"observed,omitempty"`
	Network  *Network   `json:"network,omitempty"`
	HTTP     *HTTP      `json:"http,omitempty"`
	Tech     *Tech      `json:"tech,omitempty"`
	TLS      *TLS       `json:"tls,omitempty"`
	Scan     *ScanState `json:"scan,omitempty"`
}

// MarshalJSON enforces the two invariants the schema states but a Go zero value
// cannot: the required arrays serialize as [] rather than null, and the constant
// $schema/version are always stamped. Doing it here rather than at each
// construction site means a target built in Go is indistinguishable on the wire
// from one decoded off disk.
func (t TargetDocument) MarshalJSON() ([]byte, error) {
	type alias TargetDocument // shed the method set, or this recurses
	out := alias(t)
	out.Schema = TargetSchemaRef
	out.Version = TargetVersion
	if out.ID == "" && out.Host != "" {
		out.ID = out.Host
	}
	if out.Profiles == nil {
		out.Profiles = []string{}
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	return json.Marshal(out)
}

// CredentialMode says where a provider process obtains credentials. Neither
// mode permits secret material in the inventory: configured means non-secret
// profile names, role names or credential-file paths in Arguments.
type CredentialMode string

const (
	CredentialAmbient    CredentialMode = "ambient"
	CredentialConfigured CredentialMode = "configured"
)

func (m CredentialMode) Valid() bool {
	return m == CredentialAmbient || m == CredentialConfigured
}

// MarshalJSON applies the same required-array rule to the editable projection.
func (c Curated) MarshalJSON() ([]byte, error) {
	type alias Curated
	out := alias(c)
	if out.Profiles == nil {
		out.Profiles = []string{}
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	return json.Marshal(out)
}

// Observed records probe liveness. A failed probe updates only LastAttempt and
// Error, leaving the last successful snapshot in the other sections intact.
type Observed struct {
	FirstObserved string `json:"first_observed,omitempty"`
	LastSeen      string `json:"last_seen,omitempty"`
	LastAttempt   string `json:"last_attempt,omitempty"`
	Error         string `json:"error,omitempty"`

	// Failure classifies Error so the inventory can badge and filter on it. The
	// message says what happened to one request; this says which kind of problem
	// the host has.
	Failure Failure `json:"failure,omitempty"`
}

// Network is the resolved addressing and edge metadata.
type Network struct {
	IP        string   `json:"ip,omitempty"`
	IPv4      []string `json:"ipv4,omitempty"`
	IPv6      []string `json:"ipv6,omitempty"`
	CNAME     []string `json:"cname,omitempty"`
	Resolvers []string `json:"resolvers,omitempty"`
	OpenPorts []int    `json:"open_ports,omitempty"`
	CDN       *CDN     `json:"cdn,omitempty"`
	ASN       *ASN     `json:"asn,omitempty"`
}

// CDN is present whenever any CDN signal was seen; Enabled is required by the
// schema and defaults to false when only a name or type was reported.
type CDN struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type,omitempty"`
}

// ASN carries an autonomous system. Number is a pointer because the schema
// allows 0.
type ASN struct {
	Number  *int   `json:"number,omitempty"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
	Range   string `json:"range,omitempty"`
}

// HTTP is the primary responding endpoint. Title, Webserver, ContentType,
// Location and ResponseTime are pointers: the schema permits "" and the
// normalizer preserves it.
type HTTP struct {
	URL          string   `json:"url,omitempty"`
	Scheme       string   `json:"scheme,omitempty"`
	Port         int      `json:"port,omitempty"`
	StatusCode   int      `json:"status_code,omitempty"`
	Title        *string  `json:"title,omitempty"`
	Webserver    *string  `json:"webserver,omitempty"`
	ContentType  *string  `json:"content_type,omitempty"`
	Location     *string  `json:"location,omitempty"`
	ResponseTime *string  `json:"response_time,omitempty"`
	KnownPaths   []string `json:"known_paths,omitempty"`
	LoginMethods []string `json:"login_methods,omitempty"`
	Failed       *bool    `json:"failed,omitempty"`
}

// Tech is the detected application stack.
type Tech struct {
	Names []string `json:"names,omitempty"`
	CPE   []CPE    `json:"cpe,omitempty"`
}

// CPE is one Common Platform Enumeration entry. Product and Vendor are pointers
// because a bare CPE string is split positionally and may yield "".
type CPE struct {
	Product *string `json:"product,omitempty"`
	Vendor  *string `json:"vendor,omitempty"`
	CPE     string  `json:"cpe"`
}

// TLS is the observed certificate and negotiated parameters. Every string is a
// pointer: none carry minLength in the schema.
type TLS struct {
	TLSVersion          *string  `json:"tls_version,omitempty"`
	Cipher              *string  `json:"cipher,omitempty"`
	SubjectDN           *string  `json:"subject_dn,omitempty"`
	SubjectCN           *string  `json:"subject_cn,omitempty"`
	SubjectOrg          []string `json:"subject_org,omitempty"`
	SubjectAN           []string `json:"subject_an,omitempty"`
	IssuerDN            *string  `json:"issuer_dn,omitempty"`
	IssuerCN            *string  `json:"issuer_cn,omitempty"`
	IssuerOrg           []string `json:"issuer_org,omitempty"`
	NotBefore           *string  `json:"not_before,omitempty"`
	NotAfter            *string  `json:"not_after,omitempty"`
	Serial              *string  `json:"serial,omitempty"`
	Expired             *bool    `json:"expired,omitempty"`
	SelfSigned          *bool    `json:"self_signed,omitempty"`
	Mismatched          *bool    `json:"mismatched,omitempty"`
	Revoked             *bool    `json:"revoked,omitempty"`
	Untrusted           *bool    `json:"untrusted,omitempty"`
	WildcardCertificate *bool    `json:"wildcard_certificate,omitempty"`
	FingerprintHash     *string  `json:"fingerprint_hash,omitempty"`
}

// ScanState is the outcome of the last clean scan that covered this host.
type ScanState struct {
	LastScan     string `json:"last_scan,omitempty"`
	LastFindings *int   `json:"last_findings,omitempty"`
}

// CuratedFields are the only fields a user may edit. Everything else is
// machine-owned and is preserved verbatim across an update.
var CuratedFields = []string{
	"class", "app", "cluster", "source", "profiles", "ports", "tags", "notes", "reason",
}

// Curated is the editable projection of a target — the body of an update.
type Curated struct {
	Class   Class  `json:"class"`
	App     string `json:"app,omitempty"`
	Cluster string `json:"cluster,omitempty"`
	Source  string `json:"source,omitempty"`
	// The list fields take either a JSON array or the comma-joined form a CLI
	// flag produces, because one operation is served on both surfaces.
	Profiles StringList `json:"profiles"`
	Ports    IntList    `json:"ports,omitempty"`
	Tags     StringList `json:"tags"`
	Notes    string     `json:"notes,omitempty"`
	Reason   string     `json:"reason,omitempty"`
}

// Curated extracts the editable projection.
func (t TargetDocument) Curated() Curated {
	return Curated{
		Class:    t.Class,
		App:      t.App,
		Cluster:  t.Cluster,
		Source:   t.Source,
		Profiles: t.Profiles,
		Ports:    t.Ports,
		Tags:     t.Tags,
		Notes:    t.Notes,
		Reason:   t.Reason,
	}
}

// Inventory is the target listing.
type Inventory struct {
	Version       int              `json:"version"`
	Zones         []string         `json:"zones"`
	Rows          []TargetDocument `json:"rows"`
	TagVocabulary []string         `json:"tagVocabulary"`
}
