package models

import (
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/flanksource/recon/internal/api"
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

	TemplateID  string  `gorm:"column:template_id"`
	Name        string  `gorm:"column:name"`
	Severity    string  `gorm:"column:severity"`
	Host        string  `gorm:"column:host"`
	MatchedAt   string  `gorm:"column:matched_at"`
	MatcherName *string `gorm:"column:matcher_name"`
	Verdict     string  `gorm:"column:verdict"`
	Type        *string `gorm:"column:type"`

	Tags      pq.StringArray `gorm:"column:tags;type:text[]"`
	Timestamp *time.Time     `gorm:"column:timestamp"`

	Extracted   pq.StringArray `gorm:"column:extracted;type:text[]"`
	Remediation *string        `gorm:"column:remediation"`
	Reference   pq.StringArray `gorm:"column:reference;type:text[]"`
	Curl        *string        `gorm:"column:curl"`
	Request     *string        `gorm:"column:request"`
	Response    *string        `gorm:"column:response"`

	Raw JSON[map[string]any] `gorm:"column:raw;type:jsonb"`

	// ResourceID is the primary subject the evidence is about, NULL for an
	// engine that names no resource recon has recorded.
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
		ID:          f.ID,
		ScanID:      f.ScanID,
		LineNo:      f.LineNo,
		TargetID:    deref(f.TargetID),
		TemplateID:  f.TemplateID,
		Name:        f.Name,
		Severity:    api.Severity(f.Severity),
		Host:        f.Host,
		MatchedAt:   f.MatchedAt,
		MatcherName: deref(f.MatcherName),
		// Only when it is not the default. Every finding is a failure unless it
		// says otherwise, so echoing "fail" onto every one of them would put a
		// field on the wire that carries no information and break the round-trip
		// an ordinary finding is asserted to survive.
		Verdict: manualOnly(f.Verdict),
		Type:        deref(f.Type),
		Tags:        stringSlice(f.Tags),
		Extracted:   stringSlice(f.Extracted),
		Remediation: deref(f.Remediation),
		Reference:   stringSlice(f.Reference),
		Curl:        deref(f.Curl),
		Request:     deref(f.Request),
		Response:    deref(f.Response),
		Raw:         f.Raw.Get(),
	}
	if f.Timestamp != nil {
		finding.Timestamp = f.Timestamp.Format(time.RFC3339)
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
func FindingFrom(scanID string, lineNo int, finding api.Finding, resourceID string) Finding {
	row := Finding{
		ScanID:      scanID,
		LineNo:      lineNo,
		ResourceID:  nonEmpty(resourceID),
		TargetID:    nonEmpty(scrub(finding.TargetID)),
		TemplateID:  scrub(finding.TemplateID),
		Name:        scrub(finding.Name),
		Severity:    string(finding.Severity),
		Host:        scrub(finding.Host),
		MatchedAt:   scrub(finding.MatchedAt),
		MatcherName: nonEmpty(scrub(finding.MatcherName)),
		Verdict:     verdictOf(finding),
		Type:        nonEmpty(scrub(finding.Type)),
		// Never nil: the column is NOT NULL with a '{}' default, and GORM sends an
		// explicit NULL for a nil slice rather than letting the default apply. A
		// tagless finding is an empty list, not an absent one.
		Tags:        pq.StringArray(orEmpty(scrubAll(finding.Tags))),
		Extracted:   pq.StringArray(scrubAll(finding.Extracted)),
		Remediation: nonEmpty(scrub(finding.Remediation)),
		Reference:   pq.StringArray(scrubAll(finding.Reference)),
		Curl:        nonEmpty(scrub(finding.Curl)),
		Request:     nonEmpty(scrub(finding.Request)),
		Response:    nonEmpty(scrub(finding.Response)),
		Raw:         wrapMap(scrubMap(finding.Raw)),
	}
	if finding.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339, finding.Timestamp); err == nil {
			row.Timestamp = &parsed
		}
	}
	return row
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

func nonEmpty(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
