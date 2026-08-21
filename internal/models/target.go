package models

import (
	"time"

	"github.com/lib/pq"
	"gorm.io/gorm"

	"github.com/flanksource/recon/internal/api"
	credentialstore "github.com/flanksource/recon/internal/credentials"
)

// Target is one row of the targets table.
//
// The curated fields are typed columns because every selector filters on them.
// The machine-owned sections are jsonb: their shape follows whatever the
// discovery engines emit, and flattening them into columns would both lose the
// absent-vs-empty distinction and make an engine upgrade a schema migration.
type Target struct {
	ID             string                                    `gorm:"column:id;primaryKey"`
	Host           *string                                   `gorm:"column:host"`
	Kind           string                                    `gorm:"column:kind"`
	Provider       *string                                   `gorm:"column:provider"`
	CredentialMode *string                                   `gorm:"column:credential_mode"`
	Arguments      JSON[map[string]any]                      `gorm:"column:arguments;type:jsonb"`
	Credentials    JSON[credentialstore.ProviderCredentials] `gorm:"column:credentials;type:jsonb"`
	Class          string                                    `gorm:"column:class"`
	App            *string                                   `gorm:"column:app"`
	Cluster        *string                                   `gorm:"column:cluster"`
	Source         *string                                   `gorm:"column:source"`

	Profiles pq.StringArray `gorm:"column:profiles;type:text[]"`
	Ports    pq.Int64Array  `gorm:"column:ports;type:integer[]"`
	Tags     pq.StringArray `gorm:"column:tags;type:text[]"`
	Notes    *string        `gorm:"column:notes"`
	Reason   *string        `gorm:"column:reason"`

	Observed JSON[api.Observed]  `gorm:"column:observed;type:jsonb"`
	Network  JSON[api.Network]   `gorm:"column:network;type:jsonb"`
	HTTP     JSON[api.HTTP]      `gorm:"column:http;type:jsonb"`
	Tech     JSON[api.Tech]      `gorm:"column:tech;type:jsonb"`
	TLS      JSON[api.TLS]       `gorm:"column:tls;type:jsonb"`
	Scan     JSON[api.ScanState] `gorm:"column:scan;type:jsonb"`

	CreatedAt time.Time `gorm:"column:created_at;<-:create"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

// TableName is explicit so a gorm naming-strategy change cannot silently
// repoint the model at a different table than the HCL declares.
func (Target) TableName() string { return "targets" }

// BeforeSave resolves the absent-means-host default for kind.
//
// The column's SQL default cannot do this: gorm names every field in its
// INSERT, so a Target built without a kind writes an empty string rather than
// falling back — and the CHECK rejects it. Applying it here rather than at each
// construction site means a row built anywhere is valid, including by code
// written before cloud accounts existed.
func (t *Target) BeforeSave(*gorm.DB) error {
	t.Kind = api.TargetKind(t.Kind).String()
	if t.ID == "" && t.Host != nil {
		t.ID = *t.Host
	}
	return nil
}

// Document projects the row onto the wire type. $schema and version are
// synthesised here and never stored: they are constants in the JSON Schema, so
// persisting them would just be a column that can only hold one value.
func (t Target) Document() api.TargetDocument {
	return api.TargetDocument{
		Schema:  api.TargetSchemaRef,
		Version: api.TargetVersion,
		ID:      t.ID,
		Host:    deref(t.Host),
		// Host is the schema default and remains absent on the wire.
		Kind:           kindOf(t.Kind),
		Provider:       deref(t.Provider),
		CredentialMode: api.CredentialMode(deref(t.CredentialMode)),
		Arguments:      t.Arguments.Get(),
		Credentials:    api.ProviderCredentialsFromStored(t.Credentials.V),
		Class:          api.Class(t.Class),
		App:            deref(t.App),
		Cluster:        deref(t.Cluster),
		Source:         deref(t.Source),
		Profiles:       stringSlice(t.Profiles),
		Ports:          ints(t.Ports),
		Tags:           stringSlice(t.Tags),
		Notes:          deref(t.Notes),
		Reason:         deref(t.Reason),
		Observed:       t.Observed.V,
		Network:        t.Network.V,
		HTTP:           t.HTTP.V,
		Tech:           t.Tech.V,
		TLS:            t.TLS.V,
		Scan:           t.Scan.V,
	}
}

// TargetFromDocument builds a row from a full document — the import path, where
// the machine-owned sections arrive alongside the curated ones.
func TargetFromDocument(document api.TargetDocument) Target {
	arguments := JSON[map[string]any]{}
	if document.Arguments != nil {
		arguments = Wrap(&document.Arguments)
	}
	credentials := JSON[credentialstore.ProviderCredentials]{}
	if document.Credentials != nil {
		stored := document.Credentials.Stored()
		credentials = Wrap(&stored)
	}
	return Target{
		ID: document.GetID(), Host: ref(document.Host),
		// String() resolves the absent-means-host default, because the column is
		// NOT NULL and an empty string is not one of the values it permits.
		Kind:           document.Kind.String(),
		Provider:       ref(document.Provider),
		CredentialMode: ref(string(document.CredentialMode)),
		Arguments:      arguments,
		Credentials:    credentials,
		Class:          string(document.Class),
		App:            ref(document.App),
		Cluster:        ref(document.Cluster),
		Source:         ref(document.Source),
		Profiles:       pq.StringArray(document.Profiles),
		Ports:          int64s(document.Ports),
		Tags:           pq.StringArray(orEmpty(document.Tags)),
		Notes:          ref(document.Notes),
		Reason:         ref(document.Reason),
		Observed:       Wrap(document.Observed),
		Network:        Wrap(document.Network),
		HTTP:           Wrap(document.HTTP),
		Tech:           Wrap(document.Tech),
		TLS:            Wrap(document.TLS),
		Scan:           Wrap(document.Scan),
	}
}

// ApplyCurated overwrites only the editable fields, leaving every machine-owned
// section untouched. This is the update path: the API accepts a Curated body,
// never a whole document, so an observation cannot be forged through it.
func (t *Target) ApplyCurated(curated api.Curated) {
	t.Class = string(curated.Class)
	t.App = ref(curated.App)
	t.Cluster = ref(curated.Cluster)
	t.Source = ref(curated.Source)
	t.Profiles = pq.StringArray(curated.Profiles)
	t.Ports = int64s(curated.Ports)
	t.Tags = pq.StringArray(orEmpty(curated.Tags))
	t.Notes = ref(curated.Notes)
	t.Reason = ref(curated.Reason)
}

// Zone is one DNS zone discovery enumerates.
type Zone struct {
	Zone      string    `gorm:"column:zone;primaryKey"`
	CreatedAt time.Time `gorm:"column:created_at;<-:create"`
}

func (Zone) TableName() string { return "zones" }

// ---------------------------------------------------------------- conversions

// kindOf maps the stored kind onto the wire. "host" becomes absent rather than
// explicit: it is the default in the JSON Schema, and emitting it would change
// every existing target document.
func kindOf(stored string) api.TargetKind {
	if stored == "" || stored == string(api.KindHost) {
		return ""
	}
	return api.TargetKind(stored)
}

// ref maps "" to NULL. Every curated string carries minLength: 1, so an empty
// value means absent and must not be stored as an empty string — otherwise the
// column and the wire format disagree about what absent looks like.
func ref(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// stringSlice copies a driver array into a plain slice. The copy matters: pq
// reuses its backing array across scans.
func stringSlice(values pq.StringArray) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

// orEmpty keeps a required array non-nil so it stores as '{}' rather than NULL.
func orEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// ints narrows the int64 column to the int the schema bounds to 1..65535.
func ints(values pq.Int64Array) []int {
	if values == nil {
		return nil
	}
	out := make([]int, len(values))
	for i, value := range values {
		out[i] = int(value)
	}
	return out
}

// int64s widens for storage. Nil stays nil: the schema sets minItems 1 on ports,
// so an absent list is NULL rather than an empty array.
func int64s(values []int) pq.Int64Array {
	if values == nil {
		return nil
	}
	out := make(pq.Int64Array, len(values))
	for i, value := range values {
		out[i] = int64(value)
	}
	return out
}
