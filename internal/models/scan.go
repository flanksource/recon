package models

import (
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/ocsf"
)

// Scan is one row of the scans table.
type Scan struct {
	ID   string `gorm:"column:id;primaryKey;default:generate_ulid()"`
	Name string `gorm:"column:name"`

	Engine        string  `gorm:"column:engine"`
	EngineVersion *string `gorm:"column:engine_version"`
	Profile       string  `gorm:"column:profile"`

	Selector      JSON[map[string]any] `gorm:"column:selector;type:jsonb"`
	EndpointCount int                  `gorm:"column:endpoint_count"`

	Phase      string     `gorm:"column:phase"`
	StartedAt  time.Time  `gorm:"column:started_at"`
	FinishedAt *time.Time `gorm:"column:finished_at"`
	DurationMS int64      `gorm:"column:duration_ms"`

	ExitCode *int           `gorm:"column:exit_code"`
	Error    *string        `gorm:"column:error"`
	Command  pq.StringArray `gorm:"column:command;type:text[]"`

	Stats      JSON[api.ScanStats]  `gorm:"column:stats;type:jsonb"`
	Severities JSON[map[string]int] `gorm:"column:severities;type:jsonb"`
	Muted      int                  `gorm:"column:muted"`
	ResultPath *string              `gorm:"column:result_path"`

	CreatedAt time.Time `gorm:"column:created_at;<-:create"`
}

// TableName is explicit so a gorm naming-strategy change cannot repoint the
// model at a different table than the HCL declares.
func (Scan) TableName() string { return "scans" }

// ScanOutput is the bounded process evidence loaded only for one scan.
type ScanOutput struct {
	ScanID          string `gorm:"column:scan_id;primaryKey"`
	Stdout          string `gorm:"column:stdout"`
	Stderr          string `gorm:"column:stderr"`
	StdoutTruncated bool   `gorm:"column:stdout_truncated"`
	StderrTruncated bool   `gorm:"column:stderr_truncated"`
}

func (ScanOutput) TableName() string { return "scan_outputs" }

// Document projects the row onto the wire type.
//
// Timestamps are formatted without a zone deliberately: the previous
// implementation wrote "2026-08-08T23:18:40" and the frontend sorts these as
// strings, so emitting an offset here would reorder the runs list.
func (s Scan) Document(findings int, hosts []string, label string) api.Scan {
	scan := api.Scan{
		ID:            s.ID,
		Name:          s.Name,
		Engine:        s.Engine,
		EngineVersion: deref(s.EngineVersion),
		Profile:       s.Profile,
		Selector:      s.Selector.Get(),
		SelectorLabel: label,
		EndpointCount: s.EndpointCount,
		Phase:         api.Phase(s.Phase),
		StartedAt:     localTimestamp(s.StartedAt),
		DurationMS:    s.DurationMS,
		Command:       stringSlice(s.Command),
		ExitCode:      s.ExitCode,
		Error:         deref(s.Error),
		Findings:      findings,
		Muted:         s.Muted,
		Severities:    s.Severities.Get(),
		Stats:         s.Stats.V,
		Hosts:         hosts,
		Result:        deref(s.ResultPath),
	}
	if s.FinishedAt != nil {
		scan.FinishedAt = localTimestamp(*s.FinishedAt)
	}
	if scan.Selector == nil {
		scan.Selector = map[string]any{}
	}
	if scan.Severities == nil {
		scan.Severities = map[string]int{}
	}
	if scan.Hosts == nil {
		scan.Hosts = []string{}
	}
	return scan
}

// localTimestamp renders a time the way the runs list expects: local wall clock,
// no offset. See Document.
func localTimestamp(t time.Time) string {
	return t.In(time.Local).Format("2006-01-02T15:04:05")
}

// Finding is one row of the findings table.
type Finding struct {
	ID       string  `gorm:"column:id;primaryKey;default:generate_ulid()"`
	ScanID   string  `gorm:"column:scan_id"`
	TargetID *string `gorm:"column:target_id"`
	// LineNo preserves the order the engine emitted findings in, which is the
	// order the results file has and the UI renders.
	LineNo int `gorm:"column:line_no"`

	// CheckID and Engine are the half of a finding's identity that is not the
	// resource, and the columns the lifecycle, the catalogue and stored mute
	// rules all key on. OCSF records both as well — in finding_info.uid and
	// metadata.product.name — but a jsonb path cannot carry an index.
	CheckID string `gorm:"column:check_id"`
	Engine  string `gorm:"column:engine"`
	Verdict string `gorm:"column:verdict"`

	// Host and MatchedAt are evidence locations rather than resources, and have
	// no OCSF equivalent. Both are what the UI groups and searches by.
	Host      string `gorm:"column:host"`
	MatchedAt string `gorm:"column:matched_at"`

	// Tags have no OCSF equivalent either. store/checks.go builds the check
	// catalogue from them and the UI filters on them, so they stay an indexed
	// column; they are also projected into finding_info.types.
	Tags pq.StringArray `gorm:"column:tags;type:text[]"`

	// The OCSF scalars, which are what is filtered and sorted on. Every one of
	// class_uid, category_uid, type_uid, activity_id, severity_id and time is
	// required by the schema, so none of them is nullable.
	ClassUID     int        `gorm:"column:class_uid"`
	CategoryUID  int        `gorm:"column:category_uid"`
	TypeUID      int64      `gorm:"column:type_uid"`
	ActivityID   int        `gorm:"column:activity_id"`
	SeverityID   int        `gorm:"column:severity_id"`
	StatusID     *int       `gorm:"column:status_id"`
	StatusCode   *string    `gorm:"column:status_code"`
	StatusDetail *string    `gorm:"column:status_detail"`
	Time         *time.Time `gorm:"column:time"`

	// One jsonb column per OCSF object rather than a single blob holding the
	// whole record. The list paths select what they render and no more — the
	// fix that stopped a page of findings dragging every engine's payload
	// through the database — and one column would put that back.
	FindingInfo     JSON[ocsf.FindingInfo]     `gorm:"column:finding_info;type:jsonb"`
	Metadata        JSON[ocsf.Metadata]        `gorm:"column:metadata;type:jsonb"`
	Remediation     JSON[ocsf.Remediation]     `gorm:"column:remediation;type:jsonb"`
	Cloud           JSON[ocsf.Cloud]           `gorm:"column:cloud;type:jsonb"`
	Vulnerabilities JSON[[]ocsf.Vulnerability] `gorm:"column:vulnerabilities;type:jsonb"`
	Observables     JSON[[]ocsf.Observable]    `gorm:"column:observables;type:jsonb"`
	Unmapped        JSON[map[string]any]       `gorm:"column:unmapped;type:jsonb"`

	// Evidences is the one unbounded thing a finding carries: an HTTP exchange,
	// a control's assertions, a block of matched source. It is excluded from
	// every list path and truncated past a limit, the way scan_outputs already
	// bounds stdout and stderr — because nothing else did, and the record it
	// replaced grew without any limit at all.
	Evidences          JSON[[]ocsf.Evidences] `gorm:"column:evidences;type:jsonb"`
	EvidencesTruncated bool                   `gorm:"column:evidences_truncated"`

	// ResourceID is the primary subject the evidence is about, NULL for an
	// engine that names no resource recon has recorded. Every subject it names
	// lives in finding_resources.
	ResourceID *string `gorm:"column:resource_id"`
}

// TableName is explicit; see Scan.TableName.
func (Finding) TableName() string { return "findings" }

// FindingResource links a finding to every subject its record named.
//
// A row per (finding, resource) rather than a column on findings, because a
// check that fails against forty buckets names forty and the verdict is about
// one of them. findings.resource_id stays the canonical subject the lifecycle
// keys on; this is the full list.
type FindingResource struct {
	FindingID  string `gorm:"column:finding_id;primaryKey"`
	ResourceID string `gorm:"column:resource_id;primaryKey"`
	Ordinal    int    `gorm:"column:ordinal"`
}

func (FindingResource) TableName() string { return "finding_resources" }

// Document projects the row onto the wire type.
// Document renders the stored row, given the subjects it names.
//
// Resources are passed in rather than recovered here, because they cannot be
// recovered here. A resource is keyed by (provider, scope, uid) and OCSF
// carries only the uid on each entry of its resources array — at 1.5.0 the
// account sits once at the event level, in cloud.account.uid. Re-reading the
// stored record therefore yields references that fail ResourceKey.Validate, and
// every consumer that needs a key silently stops matching. The caller joins
// finding_resources, which resolves to rows that hold the whole key.
//
// A finding whose engine named nothing recon recorded gets the synthesised
// reference instead, which is what nuclei and the filesystem scanners produce.
func (f Finding) Document(resources []api.ResourceRef) api.Finding {
	finding := api.Finding{
		DetectionFinding: ocsf.DetectionFinding{
			ClassUID:    f.ClassUID,
			CategoryUID: f.CategoryUID,
			TypeUID:     f.TypeUID,
			ActivityID:  ocsf.ActivityID(f.ActivityID),
			SeverityID:  ocsf.SeverityID(f.SeverityID),

			StatusCode:   deref(f.StatusCode),
			StatusDetail: deref(f.StatusDetail),

			FindingInfo:     f.FindingInfo.V,
			Metadata:        f.Metadata.V,
			Remediation:     f.Remediation.V,
			Cloud:           f.Cloud.V,
			Vulnerabilities: unwrapSlice(f.Vulnerabilities),
			Observables:     unwrapSlice(f.Observables),
			Unmapped:        f.Unmapped.Get(),
			Evidences:       unwrapSlice(f.Evidences),
		},
		ID:        f.ID,
		ScanID:    f.ScanID,
		LineNo:    f.LineNo,
		TargetID:  deref(f.TargetID),
		CheckID:   f.CheckID,
		Engine:    f.Engine,
		Host:      f.Host,
		MatchedAt: f.MatchedAt,
		// Only when it is not the default. Every finding is a failure unless it
		// says otherwise, so echoing "fail" onto every one of them would put a
		// field on the wire that carries no information and break the round-trip
		// an ordinary finding is asserted to survive.
		Verdict: manualOnly(f.Verdict),
		Tags:    stringSlice(f.Tags),
	}
	if f.StatusID != nil {
		finding.StatusID = ocsf.StatusID(*f.StatusID)
	}
	if f.Time != nil {
		finding.Time = f.Time.UnixMilli()
	}
	if finding.Tags == nil {
		finding.Tags = []string{}
	}
	finding.Resources = resources
	if len(finding.Resources) == 0 {
		if fallback := finding.ResourceFallback(); !fallback.Empty() {
			finding.Resources = []api.ResourceRef{fallback}
		}
	}
	// resource_id is the subject the verdict is about, and the relation is
	// ordered by the position the record named each in — so the canonical one is
	// first and already carries its id. Stamping it here covers the synthesised
	// reference, which resolves to no row of its own.
	if f.ResourceID != nil && len(finding.Resources) > 0 && finding.Resources[0].ID == "" {
		finding.Resources[0].ID = *f.ResourceID
	}
	return finding
}

// FindingFrom builds a row from a parsed finding.
//
// Every string is scrubbed of NUL on the way in. A finding carries the raw
// request and response an engine saw, and a scanner that probes anything binary
// — a TLS handshake, a compressed body, a network protocol — sees NUL bytes
// routinely. Postgres accepts them in neither text nor jsonb, so one such
// response used to abort the insert for the entire scan and lose every finding
// in it along with the run's terminal status.
// resourceID is the resource the finding is about, empty for an engine that
// names none — a NULL foreign key is skipped entirely, so the nuclei hot path
// pays nothing for the column existing.
// MaxEvidenceBytes bounds the one part of a finding that has no natural size.
//
// scan_outputs already bounds stdout and stderr this way, with an explicit
// truncation flag so a clipped value is visibly clipped rather than quietly
// short. The record this replaced had no limit anywhere: one provider document
// runs to 95KB, every one of them was stored, and each was shipped whole to
// Mission Control and marshalled into every report.
const MaxEvidenceBytes = 64 * 1024

func FindingFrom(scanID string, lineNo int, finding api.Finding, resourceID string) Finding {
	scrubRecord(&finding.DetectionFinding)
	evidences, truncated := boundEvidence(finding.Evidences)
	row := Finding{
		ScanID:     scanID,
		LineNo:     lineNo,
		ResourceID: nonEmpty(resourceID),
		TargetID:   nonEmpty(scrub(finding.TargetID)),
		CheckID:    scrub(finding.CheckID),
		Engine:     scrub(finding.Engine),
		Verdict:    verdictOf(finding),
		Host:       scrub(finding.Host),
		MatchedAt:  scrub(finding.MatchedAt),
		// Never nil: the column is NOT NULL with a '{}' default, and GORM sends an
		// explicit NULL for a nil slice rather than letting the default apply. A
		// tagless finding is an empty list, not an absent one.
		Tags: pq.StringArray(orEmpty(scrubAll(finding.Tags))),

		ClassUID:    finding.ClassUID,
		CategoryUID: finding.CategoryUID,
		TypeUID:     finding.TypeUID,
		ActivityID:  int(finding.ActivityID),
		SeverityID:  int(finding.SeverityID),

		StatusCode:   nonEmpty(scrub(finding.StatusCode)),
		StatusDetail: nonEmpty(scrub(finding.StatusDetail)),

		FindingInfo:     wrap(finding.FindingInfo),
		Metadata:        wrap(finding.Metadata),
		Remediation:     wrap(finding.Remediation),
		Cloud:           wrap(finding.Cloud),
		Vulnerabilities: wrapSlice(finding.Vulnerabilities),
		Observables:     wrapSlice(finding.Observables),
		Unmapped:        wrapMap(scrubMap(finding.Unmapped)),

		Evidences:          wrapSlice(evidences),
		EvidencesTruncated: truncated,
	}
	if finding.StatusID != 0 {
		status := int(finding.StatusID)
		row.StatusID = &status
	}
	// OCSF timestamps are epoch milliseconds. Zero means the engine reported no
	// time rather than 1970, so it stays NULL.
	if finding.Time != 0 {
		stamped := time.UnixMilli(finding.Time).UTC()
		row.Time = &stamped
	}
	return row
}

// boundEvidence keeps a finding storable, reporting whether anything was cut.
//
// Whole entries are dropped from the end rather than the payload being clipped
// mid-string: an evidence entry is an object with a constraint on it, and half
// of one is not a smaller evidence entry but an invalid one.
func boundEvidence(evidences []ocsf.Evidences) ([]ocsf.Evidences, bool) {
	if len(evidences) == 0 {
		return nil, false
	}
	encoded, err := json.Marshal(evidences)
	if err == nil && len(encoded) <= MaxEvidenceBytes {
		return evidences, false
	}

	kept := make([]ocsf.Evidences, 0, len(evidences))
	for index := range evidences {
		candidate := evidences[:index+1]
		encoded, err := json.Marshal(candidate)
		if err != nil || len(encoded) > MaxEvidenceBytes {
			break
		}
		kept = evidences[:index+1]
	}
	if len(kept) == 0 {
		return nil, true
	}
	return kept, true
}

// verdictOf reads what kind of verdict a finding is, defaulting to a plain
// failure. An engine that does not distinguish says nothing and gets `fail`,
// which is what every finding was before the distinction existed.
func verdictOf(finding api.Finding) string {
	if finding.Verdict == api.VerdictManual {
		return api.VerdictManual
	}
	return api.VerdictFail
}

func manualOnly(verdict string) string {
	if verdict == api.VerdictManual {
		return api.VerdictManual
	}
	return ""
}

// nulReplacement marks where a byte Postgres cannot store used to be. The
// standard replacement character rather than deletion, so the evidence says a
// byte was dropped instead of quietly closing the gap.
const nulReplacement = "�"

// scrub removes the one character Postgres accepts in neither text nor jsonb.
func scrub(value string) string {
	if !strings.ContainsRune(value, 0) {
		return value
	}
	return strings.ReplaceAll(value, "\x00", nulReplacement)
}

func scrubAll(values []string) []string {
	for i, value := range values {
		values[i] = scrub(value)
	}
	return values
}

// scrubMap walks a decoded JSON document. Keys are scrubbed as well as values:
// an engine's raw record is arbitrary JSON, and a NUL anywhere in it fails the
// whole insert.
func scrubMap(document map[string]any) map[string]any {
	if document == nil {
		return nil
	}
	out := make(map[string]any, len(document))
	for key, value := range document {
		out[scrub(key)] = scrubValue(value)
	}
	return out
}

// scrubRecord removes NUL from every string the OCSF record carries, in place.
//
// The flat columns are scrubbed one by one because there are few of them and
// naming each is clearer. The record is not: what used to be the `response`
// column is now evidences[].http_response.message, the description is
// finding_info.desc, and a scanner that probes a binary protocol sees NUL bytes
// in exactly those places. Scrubbing only the columns would have moved the
// abort-the-whole-scan failure from one part of the row into another.
//
// Reflective rather than field by field for the same reason the exemplar is:
// the record is generated from OCSF's schema, so a hand-written list of its
// string fields is a second copy that goes stale silently the first time the
// schema grows one.
//
// It mutates rather than copies. The alternative is deep-copying every finding
// on the ingest path to avoid touching the engine's in-memory record, and a
// record holding a byte Postgres cannot store is not worth preserving intact.
func scrubRecord(record *ocsf.DetectionFinding) {
	scrubReflect(reflect.ValueOf(record).Elem())
}

func scrubReflect(value reflect.Value) {
	switch value.Kind() {
	case reflect.String:
		if value.CanSet() {
			value.SetString(scrub(value.String()))
		}

	case reflect.Pointer:
		if !value.IsNil() {
			scrubReflect(value.Elem())
		}

	case reflect.Slice:
		// json.RawMessage: a NUL inside the encoded document fails the jsonb
		// cast exactly the way one in a text column fails the insert.
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.CanSet() {
				value.SetBytes([]byte(scrub(string(value.Bytes()))))
			}
			return
		}
		for i := range value.Len() {
			scrubReflect(value.Index(i))
		}

	case reflect.Map:
		// Keys as well as values: `unmapped` is arbitrary JSON, and a NUL
		// anywhere in it fails the same cast. Map values are not addressable, so
		// each is scrubbed in a settable copy and written back.
		for _, key := range value.MapKeys() {
			held := reflect.New(value.Type().Elem()).Elem()
			held.Set(value.MapIndex(key))
			scrubReflect(held)

			scrubbed := key
			if key.Kind() == reflect.String && scrub(key.String()) != key.String() {
				scrubbed = reflect.ValueOf(scrub(key.String())).Convert(key.Type())
				value.SetMapIndex(key, reflect.Value{})
			}
			value.SetMapIndex(scrubbed, held)
		}

	case reflect.Interface:
		if value.IsNil() {
			return
		}
		held := reflect.New(value.Elem().Type()).Elem()
		held.Set(value.Elem())
		scrubReflect(held)
		if value.CanSet() {
			value.Set(held)
		}

	case reflect.Struct:
		for i := range value.NumField() {
			if value.Type().Field(i).IsExported() {
				scrubReflect(value.Field(i))
			}
		}
	}
}

func scrubValue(value any) any {
	switch typed := value.(type) {
	case string:
		return scrub(typed)
	case map[string]any:
		return scrubMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = scrubValue(item)
		}
		return out
	default:
		return value
	}
}

// wrapMap stores a map as jsonb, keeping an absent map as SQL NULL rather than
// an empty object.
func wrapMap(value map[string]any) JSON[map[string]any] {
	if value == nil {
		return JSON[map[string]any]{}
	}
	return JSON[map[string]any]{V: &value}
}

// wrap stores an OCSF object, keeping an absent one as SQL NULL.
//
// NULL rather than `{}`: an object OCSF marks optional and an engine did not
// report is absent, and a column full of empty objects cannot be told apart
// from one where every engine reported nothing.
func wrap[T any](value *T) JSON[T] {
	if value == nil {
		return JSON[T]{}
	}
	return JSON[T]{V: value}
}

// wrapSlice stores a repeated OCSF attribute, keeping an empty one as NULL for
// the same reason.
func wrapSlice[T any](values []T) JSON[[]T] {
	if len(values) == 0 {
		return JSON[[]T]{}
	}
	return JSON[[]T]{V: &values}
}

func unwrapSlice[T any](stored JSON[[]T]) []T {
	if stored.V == nil {
		return nil
	}
	return *stored.V
}

func nonEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
