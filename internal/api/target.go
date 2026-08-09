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
	TargetVersion   = 1
)

// Class is the curated classification that decides whether a target is in scope
// for a scan and whether an intrusive scan needs confirmation.
type Class string

const (
	ClassPublic      Class = "public"
	ClassProd        Class = "prod"
	ClassNonProd     Class = "non-prod"
	ClassInternal    Class = "internal"
	ClassDeactivated Class = "deactivated"
)

// Classes lists every valid class in schema order.
func Classes() []Class {
	return []Class{ClassPublic, ClassProd, ClassNonProd, ClassInternal, ClassDeactivated}
}

// Risky reports whether scanning this class with an intrusive profile requires
// explicit confirmation. An unknown class — a host absent from the inventory —
// is risky, which is why the caller passes "" for one.
func (c Class) Risky() bool {
	return c == ClassProd || c == ClassPublic || c == ""
}

// TargetDocument is one host as the API returns it.
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
	Host    string `json:"host"`

	Class    Class    `json:"class"`
	App      string   `json:"app,omitempty"`
	Cluster  string   `json:"cluster,omitempty"`
	Source   string   `json:"source,omitempty"`
	Profiles []string `json:"profiles"`
	Ports    []int    `json:"ports,omitempty"`
	Tags     []string `json:"tags"`
	Notes    string   `json:"notes,omitempty"`
	Reason   string   `json:"reason,omitempty"`

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
	if out.Profiles == nil {
		out.Profiles = []string{}
	}
	if out.Tags == nil {
		out.Tags = []string{}
	}
	return json.Marshal(out)
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
	Class    Class    `json:"class"`
	App      string   `json:"app,omitempty"`
	Cluster  string   `json:"cluster,omitempty"`
	Source   string   `json:"source,omitempty"`
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
