package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/configdb"
	"github.com/flanksource/recon/internal/ocsf"
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
	Description      string   `json:"Description"`
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
	Findings []api.Finding
	Examined int
	Artifact string
	// ArtifactType is trivy's own word for what it scanned — container_image,
	// filesystem, repository — kept because it is the resource's type and the
	// only thing distinguishing an image called `app` from a directory of the
	// same name.
	ArtifactType string
	templates    map[string]struct{}
}

// Resource is the one subject a trivy report is about.
//
// One per report rather than one per package: trivy scans an artifact and
// reports what is inside it, so the artifact is the thing that has a lifecycle
// and the packages are its contents. No verdicts — trivy is a matcher, and a
// package it did not report a CVE for was not asserted to be clean, which is
// why PassRecorded is false for this engine and why nothing here resolves.
func (p *parsed) Resource(targetID string) api.Resource {
	kind := p.ArtifactType
	if kind == "" {
		kind = "unknown"
	}
	artifact := p.Artifact
	if artifact == "" {
		artifact = targetID
	}
	return api.Resource{
		Provider: "trivy", Scope: targetID, UID: artifact,
		Kind: api.KindArtifact, Type: kind, Name: artifact,
		TargetID: targetID,
		ExternalIDs: configdb.ExternalIDs(artifact, artifact),
	}
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
	found := &parsed{
		Artifact: d.ArtifactName, ArtifactType: d.ArtifactType,
		templates: map[string]struct{}{},
	}
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
				finding, keep, err := entries.build(raw, context)
				if err != nil {
					return nil, err
				}
				if !keep {
					continue
				}
				found.templates[finding.CheckID] = struct{}{}
				found.Findings = append(found.Findings, finding)
			}
		}
	}
	resource := found.Resource(targetID).Ref()
	for index := range found.Findings {
		found.Findings[index].Resources = []api.ResourceRef{resource}
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

// record is what one trivy finding contributes, whichever of the four kinds of
// record it came from.
//
// Trivy reports four things that are alike enough to store identically and
// different enough that each used to build its own api.Finding literal — four
// copies of the same eleven fields, which is four places for the OCSF skeleton
// to drift. Class is what used to be written to matcher_name, a column that
// meant the record's kind here and something else in every other engine.
type normalised struct {
	CheckID     string
	Title       string
	Desc        string
	Severity    api.Severity
	Class       string
	MatchedAt   string
	Tags        []string
	Time        string
	Remediation string
	References  []string
	Evidence    map[string]any
	Vulnerable  []ocsf.Vulnerability
}

// finding renders one trivy record as an OCSF Detection Finding.
func (c findingContext) finding(r normalised) (api.Finding, error) {
	evidences, err := recordEvidence(r)
	if err != nil {
		return api.Finding{}, err
	}
	types := append([]string{r.Class}, r.Tags...)
	finding := api.Finding{
		DetectionFinding: ocsf.DetectionFinding{
			ClassUID:    ocsf.ClassUID,
			CategoryUID: ocsf.CategoryUID,
			ActivityID:  ocsf.ActivityIDCreate,
			TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
			SeverityID:  api.SeverityID(r.Severity),
			StatusID:    ocsf.StatusIDNew,
			Time:        epochMillis(r.Time),

			FindingInfo: &ocsf.FindingInfo{
				UID:   r.CheckID,
				Title: r.Title,
				Desc:  r.Desc,
				Types: types,
			},
			// No profile: trivy scans an image or a filesystem, which has no
			// cloud account to name.
			Metadata: &ocsf.Metadata{
				Version:   ocsf.Version,
				EventCode: r.CheckID,
				Product: &ocsf.Product{
					Name:       EngineName,
					VendorName: api.Vendor,
				},
			},
			Vulnerabilities: r.Vulnerable,
			Evidences:       evidences,
		},
		TargetID:  c.TargetID,
		CheckID:   r.CheckID,
		Engine:    EngineName,
		Host:      c.Host,
		MatchedAt: r.MatchedAt,
		Tags:      c.tags(r.Tags...),
	}
	if r.Remediation != "" || len(r.References) > 0 {
		finding.Remediation = &ocsf.Remediation{Desc: r.Remediation, References: r.References}
	}
	return finding, nil
}

// actionable adapts one built finding to the reader's triple. Only
// misconfigurationFinding ever answers no, and it does so before building.
func actionable(finding api.Finding, err error) (api.Finding, bool, error) {
	if err != nil {
		return api.Finding{}, false, err
	}
	return finding, true, nil
}

// recordEvidence carries what trivy showed of the file it was reading — the
// offending lines and the cause metadata. An entry needs one of the attributes
// OCSF's at_least_one constraint names, so `data` is what carries it and a
// record with nothing to show produces no entry at all.
func recordEvidence(r normalised) ([]ocsf.Evidences, error) {
	if len(r.Evidence) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(r.Evidence)
	if err != nil {
		return nil, fmt.Errorf("encode trivy evidence for %s: %w", r.CheckID, err)
	}
	return []ocsf.Evidences{{Name: r.Class, Data: encoded}}, nil
}

// epochMillis reads the timestamps trivy writes, which are RFC3339. A stamp
// that will not parse yields zero, which the store keeps as NULL rather than
// recording 1970.
func epochMillis(value string) int64 {
	if value == "" {
		return 0
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return 0
	}
	return parsed.UnixMilli()
}

func vulnerabilityFinding(raw json.RawMessage, context findingContext) (api.Finding, bool, error) {
	var record vulnerability
	if err := json.Unmarshal(raw, &record); err != nil {
		return api.Finding{}, false, fmt.Errorf("parse trivy vulnerability: %w", err)
	}
	if record.VulnerabilityID == "" {
		return api.Finding{}, false, fmt.Errorf("trivy vulnerability has no VulnerabilityID")
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

	return actionable(context.finding(normalised{
		CheckID:     record.VulnerabilityID,
		Title:       name,
		Desc:        record.Description,
		Severity:    api.ParseSeverity(record.Severity),
		Class:       "vulnerability",
		MatchedAt:   context.at(0) + ": " + record.PkgName + "@" + record.InstalledVersion,
		Tags:        tags,
		Time:        timestamp,
		Remediation: fixedBy(record),
		References:  references(record.PrimaryURL, record.References),
		// The CVE has a home OCSF defines for exactly it, rather than being
		// spelled out in tags and a title the way it had to be before.
		Vulnerable: []ocsf.Vulnerability{{
			Title:          name,
			Desc:           record.Description,
			Severity:       record.Severity,
			References:     references(record.PrimaryURL, record.References),
			FixAvailable:   record.FixedVersion != "",
			IsFixAvailable: record.FixedVersion != "",
			CVE:            &ocsf.CVE{UID: record.VulnerabilityID, Title: record.Title, Desc: record.Description},
			AffectedPackages: []ocsf.AffectedPackage{{
				Name:           record.PkgName,
				Version:        record.InstalledVersion,
				FixedInVersion: record.FixedVersion,
			}},
		}},
	}))
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
	name := record.Title
	if name == "" {
		name = record.Message
	}
	return actionable(context.finding(normalised{
		CheckID:   record.ID,
		Title:     name,
		Desc:      record.Message,
		Severity:  api.ParseSeverity(record.Severity),
		Class:     "misconfiguration",
		MatchedAt: context.at(record.CauseMetadata.StartLine),
		Tags: []string{
			"check", record.Type,
			"provider", record.CauseMetadata.Provider,
			"service", record.CauseMetadata.Service,
			"avd", record.AVDID,
		},
		Time:        context.Timestamp,
		Remediation: record.Resolution,
		References:  references(record.PrimaryURL, record.References),
		// Where in the file, which is the whole of what triage needs beyond the
		// message and has no modelled home.
		Evidence: causeEvidence(record),
	}))
}

// causeEvidence is where in the scanned file the misconfiguration is, which is
// what someone fixing it opens the file to find.
func causeEvidence(record misconfiguration) map[string]any {
	cause := map[string]any{}
	if record.CauseMetadata.StartLine > 0 {
		cause["start_line"] = record.CauseMetadata.StartLine
	}
	if record.CauseMetadata.Provider != "" {
		cause["provider"] = record.CauseMetadata.Provider
	}
	if record.CauseMetadata.Service != "" {
		cause["service"] = record.CauseMetadata.Service
	}
	if record.Message != "" {
		cause["message"] = record.Message
	}
	if len(cause) == 0 {
		return nil
	}
	return cause
}

func secretFinding(raw json.RawMessage, context findingContext) (api.Finding, bool, error) {
	var record secret
	if err := json.Unmarshal(raw, &record); err != nil {
		return api.Finding{}, false, fmt.Errorf("parse trivy secret: %w", err)
	}
	if record.RuleID == "" {
		return api.Finding{}, false, fmt.Errorf("trivy secret has no RuleID")
	}
	name := record.Title
	if name == "" {
		name = record.RuleID
	}
	return actionable(context.finding(normalised{
		CheckID:   record.RuleID,
		Title:     name,
		Severity:  api.ParseSeverity(record.Severity),
		Class:     "secret",
		MatchedAt: context.at(record.StartLine),
		Tags:      []string{"category", record.Category},
		Time:      context.Timestamp,
		// The matched text is deliberately not lifted out of the record. Trivy
		// masks it before writing the report, and copying the masked form into
		// a typed field would only invite someone to un-mask it later. The line
		// number is the whole of what is carried.
		Remediation: "Rotate the credential and remove it from " + context.Result.Target,
		Evidence:    lineEvidence(record.StartLine),
	}))
}

// lineEvidence is where a secret was found. Deliberately only the location:
// see secretFinding on why the matched text is not carried.
func lineEvidence(line int) map[string]any {
	if line <= 0 {
		return nil
	}
	return map[string]any{"start_line": line}
}

func licenseFinding(raw json.RawMessage, context findingContext) (api.Finding, bool, error) {
	var record license
	if err := json.Unmarshal(raw, &record); err != nil {
		return api.Finding{}, false, fmt.Errorf("parse trivy license: %w", err)
	}
	if record.Name == "" {
		return api.Finding{}, false, fmt.Errorf("trivy license has no Name")
	}
	subject := record.PkgName
	if subject == "" {
		subject = record.FilePath
	}
	if subject == "" {
		subject = context.Result.Target
	}
	return actionable(context.finding(normalised{
		// Already composed, and the precedent for composing a check id where the
		// engine's own is not unique on its own: a licence name is not a check.
		CheckID:    "license/" + record.Name,
		Title:      record.Name + " licence in " + subject,
		Severity:   api.ParseSeverity(record.Severity),
		Class:      "license",
		MatchedAt:  context.at(0) + ": " + subject,
		Tags:       []string{"category", record.Category, "license", record.Name},
		Time:       context.Timestamp,
		References: compact([]string{record.Link}),
	}))
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
