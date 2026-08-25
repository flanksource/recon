package prowler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/flanksource/recon/internal/api"
)

const EngineName = "prowler"

type ocsfReport struct {
	Findings []api.Finding
	Stats    api.ScanStats
	hosts    map[string]struct{}
	// resources is every subject the report named, keyed so a resource that
	// appears in fifty checks is recorded once; order preserves the report's own,
	// so a run's rows are deterministic.
	resources map[api.ResourceKey]api.Resource
	order     []api.ResourceKey
	templates map[string]struct{}
}

// Resources returns what the report examined, in the order it first named each.
func (r ocsfReport) Resources() []api.Resource {
	out := make([]api.Resource, 0, len(r.order))
	for _, key := range r.order {
		out = append(out, r.resources[key])
	}
	return out
}

type ocsfRecord struct {
	FindingInfo struct {
		Title string `json:"title"`
	} `json:"finding_info"`
	Severity   string `json:"severity"`
	Status     string `json:"status"`
	StatusCode string `json:"status_code"`
	Time       string `json:"time_dt"`
	Metadata   struct {
		EventCode string `json:"event_code"`
	} `json:"metadata"`
	Cloud struct {
		Provider string `json:"provider"`
		Region   string `json:"region"`
		Account  struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
			Type string `json:"type"`
		} `json:"account"`
		Org struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"org"`
	} `json:"cloud"`
	Resources   []ocsfResource `json:"resources"`
	Remediation struct {
		Description string   `json:"desc"`
		References  []string `json:"references"`
	} `json:"remediation"`
	Unmapped struct {
		Provider   string              `json:"provider"`
		ProviderID string              `json:"provider_uid"`
		Categories []string            `json:"categories"`
		Compliance map[string][]string `json:"compliance"`
	} `json:"unmapped"`
}

func readOCSF(path, targetID, provider string) (report ocsfReport, err error) {
	file, err := os.Open(path)
	if err != nil {
		return ocsfReport{}, fmt.Errorf("open prowler OCSF report: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close prowler OCSF report: %w", closeErr))
		}
	}()

	decoder := json.NewDecoder(file)
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return ocsfReport{}, fmt.Errorf("parse prowler OCSF report: expected JSON array")
	}

	report = ocsfReport{
		hosts:     map[string]struct{}{},
		templates: map[string]struct{}{},
		resources: map[api.ResourceKey]api.Resource{},
	}
	for decoder.More() {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return ocsfReport{}, fmt.Errorf("parse prowler OCSF record: %w", err)
		}
		finding, record, actionable, err := parseOCSFRecord(raw, targetID, provider)
		if err != nil {
			return ocsfReport{}, err
		}
		report.Stats.Requests++
		report.Stats.Total++
		report.hosts[recordHost(record)] = struct{}{}
		report.templates[provider+"/"+record.Metadata.EventCode] = struct{}{}
		// Before the actionable check, so a passing record still records its
		// subject. That is the whole point of reading the passes: without it the
		// estate is only ever as large as its failures.
		report.collectResources(record, targetID)
		if record.StatusCode == "PASS" {
			report.Stats.Passed++
		}
		if actionable {
			report.Findings = append(report.Findings, finding)
		}
	}
	if token, err := decoder.Token(); err != nil {
		return ocsfReport{}, fmt.Errorf("parse prowler OCSF report: %w", err)
	} else if token != json.Delim(']') {
		return ocsfReport{}, fmt.Errorf("parse prowler OCSF report: expected closing JSON array")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ocsfReport{}, fmt.Errorf("parse prowler OCSF report: trailing JSON value")
	}
	report.Stats.Percent = 100
	report.Stats.Matched = float64(len(report.Findings))
	report.Stats.Hosts = float64(len(report.hosts))
	report.Stats.Templates = float64(len(report.templates))
	// Every OCSF record carries a verdict, so a report that parsed at all has
	// counted the passes — including a report in which nothing passed.
	report.Stats.PassRecorded = true
	return report, nil
}

func parseOCSFRecord(raw json.RawMessage, targetID, provider string) (api.Finding, ocsfRecord, bool, error) {
	var record ocsfRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return api.Finding{}, record, false, fmt.Errorf("parse prowler OCSF record: %w", err)
	}
	if err := validateOCSFRecord(record); err != nil {
		return api.Finding{}, record, false, err
	}
	if record.StatusCode == "PASS" || isSuppressed(record) {
		return api.Finding{}, record, false, nil
	}

	var source map[string]any
	if err := json.Unmarshal(raw, &source); err != nil {
		return api.Finding{}, record, false, fmt.Errorf("preserve prowler OCSF record: %w", err)
	}
	finding := api.Finding{
		TargetID:    targetID,
		TemplateID:  provider + "/" + record.Metadata.EventCode,
		Name:        recordTitle(record),
		Severity:    prowlerSeverity(record.Severity),
		Host:        recordHost(record),
		MatchedAt:   matchedAt(record),
		MatcherName: record.StatusCode,
		Verdict:     recordVerdict(record),
		Type:        EngineName,
		Tags:        recordTags(record),
		Timestamp:   record.Time,
		Remediation: record.Remediation.Description,
		Reference:   compact(record.Remediation.References),
		Raw:         source,
	}
	// Projected from the typed record, in the one place that also decides how
	// the run's resource rows are keyed — see subjects. Reading it back out of
	// the preserved JSON cannot produce a whole key, because OCSF does not put
	// one there.
	finding.Resources = resourceRefs(record)
	return finding, record, true, nil
}

func validateOCSFRecord(record ocsfRecord) error {
	if record.Metadata.EventCode == "" {
		return fmt.Errorf("prowler OCSF record: metadata.event_code is required")
	}
	switch record.StatusCode {
	case "FAIL", "MANUAL", "PASS":
	default:
		return fmt.Errorf("prowler OCSF record %s: unknown status_code %q", record.Metadata.EventCode, record.StatusCode)
	}
	if recordHost(record) == "" {
		return fmt.Errorf("prowler OCSF record %s: account or provider identity is required", record.Metadata.EventCode)
	}
	return nil
}

// recordVerdict translates prowler's status code into the one the lifecycle
// keys on. MANUAL means the check cannot decide and a person has to, which is
// the only status prowler reports that is neither a pass nor a failure.
//
// Empty for a plain failure rather than "fail": that is the documented default
// on api.Finding, and stating it on every record would put a field carrying no
// information into every line of every artifact.
func recordVerdict(record ocsfRecord) string {
	if record.StatusCode == "MANUAL" {
		return api.VerdictManual
	}
	return ""
}

func recordTitle(record ocsfRecord) string {
	if record.FindingInfo.Title != "" {
		return record.FindingInfo.Title
	}
	return record.Metadata.EventCode
}

func recordHost(record ocsfRecord) string {
	for _, value := range []string{record.Cloud.Account.Name, record.Cloud.Account.UID, record.Unmapped.ProviderID} {
		if value != "" {
			return value
		}
	}
	return ""
}

func recordProvider(record ocsfRecord) string {
	if record.Cloud.Provider != "" {
		return record.Cloud.Provider
	}
	return record.Unmapped.Provider
}

func matchedAt(record ocsfRecord) string {
	if len(record.Resources) == 0 {
		return recordHost(record)
	}
	if record.Resources[0].UID != "" {
		return record.Resources[0].UID
	}
	if record.Resources[0].Name != "" {
		return record.Resources[0].Name
	}
	return recordHost(record)
}

func prowlerSeverity(value string) api.Severity {
	if strings.EqualFold(strings.TrimSpace(value), "informational") {
		return api.SeverityInfo
	}
	return api.ParseSeverity(value)
}

func recordTags(record ocsfRecord) []string {
	set := map[string]struct{}{}
	appendTag(set, "provider", recordProvider(record))
	if len(record.Resources) > 0 {
		appendTag(set, "service", record.Resources[0].Group.Name)
		appendTag(set, "resource-type", record.Resources[0].Type)
	}
	for _, category := range record.Unmapped.Categories {
		appendTag(set, "category", category)
	}
	for framework, requirements := range record.Unmapped.Compliance {
		for _, requirement := range requirements {
			appendTag(set, "compliance", framework+":"+requirement)
		}
	}
	return sortedTags(set)
}

// sortedTags renders a tag set in a stable order, so two runs over the same
// report produce the same rows.
func sortedTags(set map[string]struct{}) []string {
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

// isSuppressed reports a record the provider itself declined to judge. It is
// not a pass and not a failure: the check did not run, so it can neither open a
// finding nor resolve one.
func isSuppressed(record ocsfRecord) bool {
	return strings.EqualFold(record.Status, "Suppressed")
}

// cutLabel splits a `key:value` label. GCP reports account labels already in
// that form; anything without a separator is not a label and is dropped.
func cutLabel(entry string) (key, value string, found bool) {
	return strings.Cut(entry, ":")
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
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
