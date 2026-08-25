package prowler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/ocsf"
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

// ocsfRecord is one record of prowler's report.
//
// The OCSF part is the generated schema rather than a hand-written projection of
// it. Prowler emits OCSF, so re-describing its fields here was a second copy of
// a published schema that could only ever drift from it — and did: the copy read
// finding_info.title and nothing else, so the description prowler puts beside it
// was invisible to recon and reachable only by digging in the raw blob.
//
// The two fields outside the embedded record are prowler's own. `time_dt` is the
// RFC3339 spelling of a timestamp OCSF also defines as epoch milliseconds under
// `time`, and prowler writes only the former. `unmapped` is OCSF's sanctioned
// escape hatch, which prowler uses for the provider identity and the compliance
// mappings that its checks are actually organised by.
type ocsfRecord struct {
	ocsf.DetectionFinding

	// Resources shadows the embedded array deliberately. OCSF types `labels` as
	// an array of strings and prowler reports GCP's as an object, which the
	// generated type cannot hold — and because a type mismatch fails the whole
	// unmarshal, the strict shape would lose the entire record rather than one
	// field. This one tolerates both forms; see resourceLabels.
	Resources []ocsfResource `json:"resources"`

	TimeDT   string `json:"time_dt"`
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
		report.templates[provider+"/"+eventCode(record)] = struct{}{}
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

	tags := recordTags(record)
	finding := api.Finding{
		DetectionFinding: ocsf.DetectionFinding{
			ClassUID:    ocsf.ClassUID,
			CategoryUID: ocsf.CategoryUID,
			ActivityID:  ocsf.ActivityIDCreate,
			TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
			SeverityID:  api.SeverityID(prowlerSeverity(record.Severity)),

			Status:       record.Status,
			StatusCode:   record.StatusCode,
			StatusDetail: record.StatusDetail,
			StatusID:     ocsf.StatusIDNew,

			Time:        recordTime(record),
			RiskDetails: record.RiskDetails,

			FindingInfo: &ocsf.FindingInfo{
				UID:   eventCode(record),
				Title: recordTitle(record),
				Desc:  recordDesc(record),
				Types: tags,
			},
			// The cloud profile is declared because prowler audits an account,
			// and declaring it is what makes cloud.provider required of these
			// records — see ocsf.Validate. An engine that scans a URL or a
			// filesystem declares nothing and is held to nothing.
			Metadata: &ocsf.Metadata{
				Version:   ocsf.Version,
				EventCode: eventCode(record),
				Profiles:  []string{api.ProfileCloud},
				Product: &ocsf.Product{
					Name:       EngineName,
					VendorName: api.Vendor,
				},
			},
			Cloud:       recordCloud(record, provider),
			Remediation: recordRemediation(record),
			Unmapped:    recordUnmapped(record),
		},
		TargetID:  targetID,
		CheckID:   provider + "/" + eventCode(record),
		Engine:    EngineName,
		Verdict:   recordVerdict(record),
		Tags:      tags,
		Host:      recordHost(record),
		MatchedAt: matchedAt(record),
	}
	// Projected from the typed record, in the one place that also decides how
	// the run's resource rows are keyed — see subjects. Reading it back out of
	// the preserved JSON cannot produce a whole key, because OCSF does not put
	// one there.
	finding.Resources = resourceRefs(record)
	return finding, record, true, nil
}

// eventCode is the check a record is about. Metadata is a pointer in the
// generated schema — OCSF marks it required, but a record that omitted it would
// otherwise panic here rather than being rejected by the validation written to
// reject it.
func eventCode(record ocsfRecord) string {
	if record.Metadata == nil {
		return ""
	}
	return record.Metadata.EventCode
}

func validateOCSFRecord(record ocsfRecord) error {
	if eventCode(record) == "" {
		return fmt.Errorf("prowler OCSF record: metadata.event_code is required")
	}
	switch record.StatusCode {
	case "FAIL", "MANUAL", "PASS":
	default:
		return fmt.Errorf("prowler OCSF record %s: unknown status_code %q", eventCode(record), record.StatusCode)
	}
	if recordHost(record) == "" {
		return fmt.Errorf("prowler OCSF record %s: account or provider identity is required", eventCode(record))
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
	if record.FindingInfo != nil && record.FindingInfo.Title != "" {
		return record.FindingInfo.Title
	}
	return eventCode(record)
}

// recordDesc is what the check is about, which prowler states and recon used to
// throw away. It was reachable only inside the preserved blob, which is where
// the browser dug for it on every engine.
func recordDesc(record ocsfRecord) string {
	if record.FindingInfo == nil {
		return ""
	}
	return record.FindingInfo.Desc
}

// recordTime reads the timestamp prowler writes.
//
// Prowler emits only `time_dt`, the RFC3339 spelling. OCSF's `time` is epoch
// milliseconds and is what the column stores, so the conversion happens here
// rather than leaving two representations to disagree. An unparseable stamp
// yields zero, which the store keeps as NULL — a finding with no time is honest
// about it rather than claiming 1970.
func recordTime(record ocsfRecord) int64 {
	if record.Time != 0 {
		return record.Time
	}
	parsed, err := time.Parse(time.RFC3339, record.TimeDT)
	if err != nil {
		return 0
	}
	return parsed.UnixMilli()
}

func recordCloud(record ocsfRecord, provider string) *ocsf.Cloud {
	cloud := ocsf.Cloud{Provider: firstNonEmpty(recordProvider(record), provider)}
	if record.Cloud != nil {
		cloud.Region = cloudRegion(record)
		cloud.Org = record.Cloud.Org
	}
	if uid := firstNonEmpty(accountUID(record), record.Unmapped.ProviderID); uid != "" {
		cloud.Account = &ocsf.Account{UID: uid, Name: accountName(record), Type: accountType(record)}
	}
	return &cloud
}

func recordRemediation(record ocsfRecord) *ocsf.Remediation {
	if record.Remediation == nil {
		return nil
	}
	remediation := ocsf.Remediation{
		Desc:       record.Remediation.Desc,
		References: compact(record.Remediation.References),
	}
	if remediation.Desc == "" && len(remediation.References) == 0 {
		return nil
	}
	return &remediation
}

// recordUnmapped keeps what prowler reports that OCSF has no field for, in
// OCSF's own escape hatch rather than a recon-specific column.
//
// The compliance mappings are the reason this is not simply dropped: prowler's
// checks are organised by framework, and "which CIS control does this fail"
// is the question a compliance audit is actually asking.
func recordUnmapped(record ocsfRecord) map[string]any {
	unmapped := map[string]any{}
	if len(record.Unmapped.Categories) > 0 {
		unmapped["categories"] = record.Unmapped.Categories
	}
	if len(record.Unmapped.Compliance) > 0 {
		unmapped["compliance"] = record.Unmapped.Compliance
	}
	if len(unmapped) == 0 {
		return nil
	}
	return unmapped
}

// The cloud identity, read through the pointers OCSF makes optional. Prowler
// reports an account on every record, but the schema does not require one and a
// record that omits it must be rejected by validation rather than by a panic
// here.
func accountUID(record ocsfRecord) string {
	if record.Cloud == nil || record.Cloud.Account == nil {
		return ""
	}
	return record.Cloud.Account.UID
}

func accountName(record ocsfRecord) string {
	if record.Cloud == nil || record.Cloud.Account == nil {
		return ""
	}
	return record.Cloud.Account.Name
}

func accountType(record ocsfRecord) string {
	if record.Cloud == nil || record.Cloud.Account == nil {
		return ""
	}
	return record.Cloud.Account.Type
}

func cloudRegion(record ocsfRecord) string {
	if record.Cloud == nil {
		return ""
	}
	return record.Cloud.Region
}

func orgUID(record ocsfRecord) string {
	if record.Cloud == nil || record.Cloud.Org == nil {
		return ""
	}
	return record.Cloud.Org.UID
}

func orgName(record ocsfRecord) string {
	if record.Cloud == nil || record.Cloud.Org == nil {
		return ""
	}
	return record.Cloud.Org.Name
}

func recordHost(record ocsfRecord) string {
	for _, value := range []string{accountName(record), accountUID(record), record.Unmapped.ProviderID} {
		if value != "" {
			return value
		}
	}
	return ""
}

func recordProvider(record ocsfRecord) string {
	if record.Cloud != nil && record.Cloud.Provider != "" {
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
