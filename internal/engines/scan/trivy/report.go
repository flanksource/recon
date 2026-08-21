package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/flanksource/recon/internal/api"
)

// reportSchemaVersion is the only report shape this parses. Trivy stamps it on
// every document; a bump means the fields below moved, and reading a document
// that says so as though it had not is how a scan silently reports nothing.
const reportSchemaVersion = 2

// document is one trivy JSON report. It is the same shape whichever provider
// produced it — the artifact differs, the results do not.
type document struct {
	SchemaVersion int      `json:"SchemaVersion"`
	CreatedAt     string   `json:"CreatedAt"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Results       []result `json:"Results"`
}

// result is one thing that was examined: a package inventory, a config file, a
// scanned file. Each finding class is kept raw as well as typed, because a
// finding is evidence and the typed fields are only what the UI filters on.
type result struct {
	Target string `json:"Target"`
	Class  string `json:"Class"`
	Type   string `json:"Type"`

	Vulnerabilities   []json.RawMessage `json:"Vulnerabilities"`
	Misconfigurations []json.RawMessage `json:"Misconfigurations"`
	Secrets           []json.RawMessage `json:"Secrets"`
	Licenses          []json.RawMessage `json:"Licenses"`
}

type vulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Status           string   `json:"Status"`
	Title            string   `json:"Title"`
	Severity         string   `json:"Severity"`
	PrimaryURL       string   `json:"PrimaryURL"`
	References       []string `json:"References"`
	CweIDs           []string `json:"CweIDs"`
	PublishedDate    string   `json:"PublishedDate"`
}

type misconfiguration struct {
	ID            string   `json:"ID"`
	AVDID         string   `json:"AVDID"`
	Title         string   `json:"Title"`
	Message       string   `json:"Message"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	Status        string   `json:"Status"`
	Type          string   `json:"Type"`
	PrimaryURL    string   `json:"PrimaryURL"`
	References    []string `json:"References"`
	CauseMetadata struct {
		Provider  string `json:"Provider"`
		Service   string `json:"Service"`
		StartLine int    `json:"StartLine"`
	} `json:"CauseMetadata"`
}

type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
}

type license struct {
	Name       string  `json:"Name"`
	Category   string  `json:"Category"`
	Severity   string  `json:"Severity"`
	PkgName    string  `json:"PkgName"`
	FilePath   string  `json:"FilePath"`
	Confidence float64 `json:"Confidence"`
	Link       string  `json:"Link"`
}

// parsed is what one report amounted to: the findings worth acting on, and the
// counts that describe everything examined to produce them.
type parsed struct {
	Findings  []api.Finding
	Examined  int
	Artifact  string
	templates map[string]struct{}
}

// ReportFile names the retained report for one provider context. Per context
// rather than one merged document, because that is the shape trivy produced and
// what someone re-running it by hand would get back.
func ReportFile(contextID string) string { return "trivy-" + slug(contextID) + ".json" }

// slug makes a context id safe to use as a file name without making two
// different ids collide on one — the replacement is escaped, not dropped.
func slug(value string) string {
	var out strings.Builder
	for _, symbol := range value {
		switch {
		case symbol >= 'a' && symbol <= 'z', symbol >= 'A' && symbol <= 'Z',
			symbol >= '0' && symbol <= '9', symbol == '-', symbol == '.':
			out.WriteRune(symbol)
		default:
			fmt.Fprintf(&out, "_%02x", symbol)
		}
	}
	if out.Len() == 0 {
		return "context"
	}
	return out.String()
}

// readReport parses one context's report.
func readReport(path, targetID string) (*parsed, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trivy report: %w", err)
	}

	var report document
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("parse trivy report %s: %w", filepath.Base(path), err)
	}
	if report.SchemaVersion != reportSchemaVersion {
		return nil, fmt.Errorf(
			"trivy report %s is schema version %d, not %d: the fields recon reads have moved",
			filepath.Base(path), report.SchemaVersion, reportSchemaVersion)
	}
	return report.parse(targetID)
}

// parse turns a report into findings.
//
// A result with no findings is still counted: "trivy read this package
// inventory and everything in it was clean" is the difference between a scan
// that worked and one that never looked, and only the counts carry it.
func (d document) parse(targetID string) (*parsed, error) {
	found := &parsed{Artifact: d.ArtifactName, templates: map[string]struct{}{}}
	host := d.ArtifactName
	if host == "" {
		host = targetID
	}

	for _, examined := range d.Results {
		context := findingContext{
			TargetID: targetID, Host: host, Timestamp: d.CreatedAt, Result: examined,
		}
		for _, entries := range []struct {
			raw   []json.RawMessage
			build func(json.RawMessage, findingContext) (api.Finding, bool, error)
		}{
			{examined.Vulnerabilities, vulnerabilityFinding},
			{examined.Misconfigurations, misconfigurationFinding},
			{examined.Secrets, secretFinding},
			{examined.Licenses, licenseFinding},
		} {
			for _, raw := range entries.raw {
				found.Examined++
				finding, actionable, err := entries.build(raw, context)
				if err != nil {
					return nil, err
				}
				if !actionable {
					continue
				}
				found.templates[finding.TemplateID] = struct{}{}
				found.Findings = append(found.Findings, finding)
			}
		}
	}
	return found, nil
}

// Stats describes what the report covered.
func (p *parsed) Stats() api.ScanStats {
	return api.ScanStats{
		Requests:  float64(p.Examined),
		Total:     float64(p.Examined),
		Matched:   float64(len(p.Findings)),
		Templates: float64(len(p.templates)),
	}
}

// findingContext is what every finding in one result shares.
type findingContext struct {
	TargetID  string
	Host      string
	Timestamp string
	Result    result
}

// at addresses a finding within the scanned artifact: which file or package
// inventory, and where in it.
func (c findingContext) at(line int) string {
	if line <= 0 {
		return c.Result.Target
	}
	return c.Result.Target + ":" + strconv.Itoa(line)
}

func (c findingContext) tags(extra ...string) []string {
	set := map[string]struct{}{}
	appendTag(set, "class", c.Result.Class)
	appendTag(set, "type", c.Result.Type)
	for index := 0; index+1 < len(extra); index += 2 {
		appendTag(set, extra[index], extra[index+1])
	}
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func vulnerabilityFinding(raw json.RawMessage, context findingContext) (api.Finding, bool, error) {
	var record vulnerability
	if err := json.Unmarshal(raw, &record); err != nil {
		return api.Finding{}, false, fmt.Errorf("parse trivy vulnerability: %w", err)
	}
	if record.VulnerabilityID == "" {
		return api.Finding{}, false, fmt.Errorf("trivy vulnerability has no VulnerabilityID")
	}
	source, err := preserve(raw, "vulnerability")
	if err != nil {
		return api.Finding{}, false, err
	}

	name := record.Title
	if name == "" {
		name = record.VulnerabilityID + " in " + record.PkgName
	}
	tags := append([]string{"package", record.PkgName, "status", record.Status}, cweTags(record.CweIDs)...)
	timestamp := record.PublishedDate
	if timestamp == "" {
		timestamp = context.Timestamp
	}

	return api.Finding{
		TargetID:    context.TargetID,
		TemplateID:  record.VulnerabilityID,
		Name:        name,
		Severity:    api.ParseSeverity(record.Severity),
		Host:        context.Host,
		MatchedAt:   context.at(0) + ": " + record.PkgName + "@" + record.InstalledVersion,
		MatcherName: "vulnerability",
		Type:        EngineName,
		Tags:        context.tags(tags...),
		Timestamp:   timestamp,
		Remediation: fixedBy(record),
		Reference:   references(record.PrimaryURL, record.References),
		Raw:         source,
	}, true, nil
}

// fixedBy states the upgrade that resolves the finding, which is the whole
// remediation for a package vulnerability. An unfixed one says so rather than
// leaving the field empty, because "there is no fix yet" is the answer someone
// triaging needs and an absent field reads as missing data.
func fixedBy(record vulnerability) string {
	if record.FixedVersion == "" {
		return "No fixed version published for " + record.PkgName + " " + record.InstalledVersion
	}
	return "Upgrade " + record.PkgName + " from " + record.InstalledVersion + " to " + record.FixedVersion
}

func misconfigurationFinding(raw json.RawMessage, context findingContext) (api.Finding, bool, error) {
	var record misconfiguration
	if err := json.Unmarshal(raw, &record); err != nil {
		return api.Finding{}, false, fmt.Errorf("parse trivy misconfiguration: %w", err)
	}
	if record.ID == "" {
		return api.Finding{}, false, fmt.Errorf("trivy misconfiguration has no ID")
	}
	// A profile may ask for the passing checks so the retained report shows the
	// whole benchmark. They are counted, not reported: a check that passed is
	// not something to act on.
	switch strings.ToUpper(record.Status) {
	case "FAIL":
	case "PASS", "EXCEPTION", "SKIP":
		return api.Finding{}, false, nil
	default:
		return api.Finding{}, false, fmt.Errorf(
			"trivy misconfiguration %s: unknown status %q", record.ID, record.Status)
	}
	source, err := preserve(raw, "misconfiguration")
	if err != nil {
		return api.Finding{}, false, err
	}

	name := record.Title
	if name == "" {
		name = record.Message
	}
	return api.Finding{
		TargetID:    context.TargetID,
		TemplateID:  record.ID,
		Name:        name,
		Severity:    api.ParseSeverity(record.Severity),
		Host:        context.Host,
		MatchedAt:   context.at(record.CauseMetadata.StartLine),
		MatcherName: "misconfiguration",
		Type:        EngineName,
		Tags: context.tags(
			"check", record.Type,
			"provider", record.CauseMetadata.Provider,
			"service", record.CauseMetadata.Service,
			"avd", record.AVDID,
		),
		Timestamp:   context.Timestamp,
		Extracted:   compact([]string{record.Message}),
		Remediation: record.Resolution,
		Reference:   references(record.PrimaryURL, record.References),
		Raw:         source,
	}, true, nil
}

func secretFinding(raw json.RawMessage, context findingContext) (api.Finding, bool, error) {
	var record secret
	if err := json.Unmarshal(raw, &record); err != nil {
		return api.Finding{}, false, fmt.Errorf("parse trivy secret: %w", err)
	}
	if record.RuleID == "" {
		return api.Finding{}, false, fmt.Errorf("trivy secret has no RuleID")
	}
	source, err := preserve(raw, "secret")
	if err != nil {
		return api.Finding{}, false, err
	}

	name := record.Title
	if name == "" {
		name = record.RuleID
	}
	return api.Finding{
		TargetID:    context.TargetID,
		TemplateID:  record.RuleID,
		Name:        name,
		Severity:    api.ParseSeverity(record.Severity),
		Host:        context.Host,
		MatchedAt:   context.at(record.StartLine),
		MatcherName: "secret",
		Type:        EngineName,
		Tags:        context.tags("category", record.Category),
		Timestamp:   context.Timestamp,
		// The matched text is deliberately not lifted out of the record. Trivy
		// masks it before writing the report, and copying the masked form into
		// a typed field would only invite someone to un-mask it later.
		Remediation: "Rotate the credential and remove it from " + context.Result.Target,
		Raw:         source,
	}, true, nil
}

func licenseFinding(raw json.RawMessage, context findingContext) (api.Finding, bool, error) {
	var record license
	if err := json.Unmarshal(raw, &record); err != nil {
		return api.Finding{}, false, fmt.Errorf("parse trivy license: %w", err)
	}
	if record.Name == "" {
		return api.Finding{}, false, fmt.Errorf("trivy license has no Name")
	}
	source, err := preserve(raw, "license")
	if err != nil {
		return api.Finding{}, false, err
	}

	subject := record.PkgName
	if subject == "" {
		subject = record.FilePath
	}
	if subject == "" {
		subject = context.Result.Target
	}
	return api.Finding{
		TargetID:    context.TargetID,
		TemplateID:  "license/" + record.Name,
		Name:        record.Name + " licence in " + subject,
		Severity:    api.ParseSeverity(record.Severity),
		Host:        context.Host,
		MatchedAt:   context.at(0) + ": " + subject,
		MatcherName: "license",
		Type:        EngineName,
		Tags:        context.tags("category", record.Category, "license", record.Name),
		Timestamp:   context.Timestamp,
		Reference:   compact([]string{record.Link}),
		Raw:         source,
	}, true, nil
}

// preserve keeps the engine's own record alongside the typed projection.
func preserve(raw json.RawMessage, kind string) (map[string]any, error) {
	var source map[string]any
	if err := json.Unmarshal(raw, &source); err != nil {
		return nil, fmt.Errorf("preserve trivy %s: %w", kind, err)
	}
	return source, nil
}

func cweTags(ids []string) []string {
	tags := make([]string, 0, len(ids)*2)
	for _, id := range ids {
		tags = append(tags, "cwe", id)
	}
	return tags
}

func references(primary string, rest []string) []string {
	return compact(append([]string{primary}, rest...))
}

func appendTag(tags map[string]struct{}, key, value string) {
	if value != "" {
		tags[key+":"+value] = struct{}{}
	}
}

func compact(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
