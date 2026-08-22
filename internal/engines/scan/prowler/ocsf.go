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
	Findings  []api.Finding
	Stats     api.ScanStats
	hosts     map[string]struct{}
	templates map[string]struct{}
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
		Account  struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"account"`
	} `json:"cloud"`
	Resources []struct {
		Name  string `json:"name"`
		UID   string `json:"uid"`
		Type  string `json:"type"`
		Group struct {
			Name string `json:"name"`
		} `json:"group"`
	} `json:"resources"`
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

	report = ocsfReport{hosts: map[string]struct{}{}, templates: map[string]struct{}{}}
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
	if record.StatusCode == "PASS" || strings.EqualFold(record.Status, "Suppressed") {
		return api.Finding{}, record, false, nil
	}

	var source map[string]any
	if err := json.Unmarshal(raw, &source); err != nil {
		return api.Finding{}, record, false, fmt.Errorf("preserve prowler OCSF record: %w", err)
	}
	return api.Finding{
		TargetID:    targetID,
		TemplateID:  provider + "/" + record.Metadata.EventCode,
		Name:        recordTitle(record),
		Severity:    prowlerSeverity(record.Severity),
		Host:        recordHost(record),
		MatchedAt:   matchedAt(record),
		MatcherName: record.StatusCode,
		Type:        EngineName,
		Tags:        recordTags(record),
		Timestamp:   record.Time,
		Remediation: record.Remediation.Description,
		Reference:   compact(record.Remediation.References),
		Raw:         source,
	}, record, true, nil
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
	tags := make([]string, 0, len(set))
	for tag := range set {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
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
