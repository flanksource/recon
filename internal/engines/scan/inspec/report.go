package inspec

import (
	"fmt"
	"sort"
	"strings"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/configdb"
)

// ExecJSON is InSpec's `json` reporter output — the exec-json schema, stable
// across InSpec 4 through 7 and published as mitre/inspecjs' ExecJSON.
//
// Only the fields recon reads are declared. The rest of the document is kept
// verbatim in the run's artifact directory, so nothing is lost by not modelling
// it here.
type ExecJSON struct {
	Platform   Platform   `json:"platform"`
	Profiles   []Profile  `json:"profiles"`
	Statistics Statistics `json:"statistics"`
	Version    string     `json:"version"`
}

// Platform is what InSpec connected to.
type Platform struct {
	Name    string `json:"name"`
	Release string `json:"release"`
}

// Profile is one benchmark, plus any profile it depends on.
type Profile struct {
	Name      string    `json:"name"`
	Title     string    `json:"title"`
	Version   string    `json:"version"`
	Copyright string    `json:"copyright"`
	Controls  []Control `json:"controls"`
}

// Control is one check in a benchmark.
type Control struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Desc  string `json:"desc"`

	// Impact is InSpec's 0.0–1.0 severity. It is the only severity a control
	// carries; the `impact 'medium'` a profile author writes is converted to a
	// number before it reaches the report.
	Impact float64 `json:"impact"`

	Descriptions   []Description  `json:"descriptions"`
	Refs           []Reference    `json:"refs"`
	Tags           map[string]any `json:"tags"`
	Code           string         `json:"code"`
	SourceLocation SourceLocation `json:"source_location"`
	Results        []Result       `json:"results"`
}

// Description is one labelled prose block — `desc 'rationale', '...'`.
type Description struct {
	Label string `json:"label"`
	Data  string `json:"data"`
}

// Reference is one citation. InSpec permits `ref` to be a URL, a URI, or free
// text, so all three shapes are declared and the first present one wins.
type Reference struct {
	Ref any    `json:"ref"`
	URL string `json:"url"`
	URI string `json:"uri"`
}

// SourceLocation is where in the profile a control is defined.
type SourceLocation struct {
	Ref  string `json:"ref"`
	Line int    `json:"line"`
}

// Result is one assertion's outcome. A control with several `describe` blocks
// produces several of these.
type Result struct {
	Status      string  `json:"status"`
	CodeDesc    string  `json:"code_desc"`
	Message     string  `json:"message"`
	Exception   string  `json:"exception"`
	SkipMessage string  `json:"skip_message"`
	Resource    string  `json:"resource"`
	RunTime     float64 `json:"run_time"`
	StartTime   string  `json:"start_time"`
}

// Statistics is the run's own summary.
type Statistics struct {
	Duration float64 `json:"duration"`
}

// The four statuses a result can carry.
const (
	StatusPassed  = "passed"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
	StatusError   = "error"
)

// Counts summarises a report by result status.
type Counts struct {
	Controls int
	Passed   int
	Failed   int
	Skipped  int
	Errored  int
}

// Count tallies every result in a report.
//
// Counted per result rather than per control: a control with twenty `describe`
// blocks is twenty assertions, and collapsing them to one pass/fail would
// report "1 failed" whether one resource is misconfigured or all twenty are.
func (r ExecJSON) Count() Counts {
	var counts Counts
	for _, profile := range r.Profiles {
		counts.Controls += len(profile.Controls)
		for _, control := range profile.Controls {
			for _, result := range control.Results {
				switch result.Status {
				case StatusPassed:
					counts.Passed++
				case StatusFailed:
					counts.Failed++
				case StatusSkipped:
					counts.Skipped++
				case StatusError:
					counts.Errored++
				}
			}
		}
	}
	return counts
}

// Findings converts a report into the findings recon stores, against the
// account the report describes.
//
// Only failures and errors become findings. A compliance run produces a few
// hundred results of which most pass, and recording those as findings would
// bury the failures and make every severity count meaningless. The complete
// report — passes, skips and all — is retained as a run artifact, so nothing is
// discarded, only classified.
func (r ExecJSON) Findings(account string) []api.Finding {
	var findings []api.Finding
	for _, profile := range r.Profiles {
		for _, control := range profile.Controls {
			for _, result := range control.Results {
				if result.Status != StatusFailed && result.Status != StatusError {
					continue
				}
				findings = append(findings, finding(account, profile, control, result))
			}
		}
	}
	return findings
}

// Resources is the account the report describes, carrying every control's
// verdict.
//
// One resource rather than one per `describe` block: InSpec's Result.Resource
// names a Ruby matcher (`google_compute_firewall`), not an addressable thing,
// so there is nothing stable to key a lifecycle on below the account. The
// account is real, is stable across runs, and is what a control's verdict is
// actually about.
//
// The verdicts are the point. InSpec reports passed/failed/skipped/error per
// control, so — unlike nuclei and trivy — a later run genuinely can resolve an
// earlier one's findings: a control that failed and now passes is fixed, and
// this is what says so. Skipped and errored are deliberately neither: a control
// that could not run has proved nothing, and counting it as a pass would
// resolve a finding on the strength of a broken check.
func (r ExecJSON) Resources(account string) []api.Resource {
	resource := accountResource(account)
	seen := map[string]struct{}{}
	for _, profile := range r.Profiles {
		for _, control := range profile.Controls {
			for _, result := range control.Results {
				if result.Status != StatusPassed {
					continue
				}
				if _, already := seen[control.ID]; already {
					continue
				}
				seen[control.ID] = struct{}{}
				resource.Passed = append(resource.Passed, control.ID)
			}
		}
	}
	// A control with twenty describe blocks passes only if every one of them
	// did: one failure anywhere makes the control a finding, and a control that
	// is both must not also claim to have passed.
	for _, profile := range r.Profiles {
		for _, control := range profile.Controls {
			for _, result := range control.Results {
				if result.Status == StatusFailed || result.Status == StatusError {
					resource.Passed = remove(resource.Passed, control.ID)
					break
				}
			}
		}
	}
	return []api.Resource{resource}
}

func remove(values []string, unwanted string) []string {
	kept := values[:0]
	for _, value := range values {
		if value != unwanted {
			kept = append(kept, value)
		}
	}
	return kept
}

func finding(account string, profile Profile, control Control, result Result) api.Finding {
	return api.Finding{
		TemplateID:  control.ID,
		Name:        title(control),
		Severity:    Severity(control.Impact),
		Host:        account,
		MatchedAt:   result.CodeDesc,
		MatcherName: result.Status,
		Type:        EngineName,
		Tags:        tagsOf(profile, control),
		Timestamp:   result.StartTime,
		Remediation: remediation(control),
		Reference:   references(control),
		Resources:   []api.ResourceRef{accountResource(account).Ref()},
		Raw: map[string]any{
			"profile": profile.Name,
			"control": control,
			"result":  result,
		},
	}
}

func accountResource(account string) api.Resource {
	return api.Resource{
		Provider: EngineName, Scope: account, UID: account,
		Kind: api.KindAccount, Name: account,
		TargetID: account,
		ExternalIDs: configdb.ExternalIDs(account, account),
	}
}

// title falls back to the control's id, because a control with no title still
// has to be identifiable in a findings list.
func title(control Control) string {
	if control.Title != "" {
		return control.Title
	}
	return control.ID
}

// Severity maps InSpec's 0.0–1.0 impact onto recon's ladder, using the bands
// InSpec itself documents and its own reporters colour by.
//
// The bands are half-open upwards, which is why `impact 'high'` (0.7) reads as
// high rather than medium.
func Severity(impact float64) api.Severity {
	switch {
	case impact >= 0.9:
		return api.SeverityCritical
	case impact >= 0.7:
		return api.SeverityHigh
	case impact >= 0.4:
		return api.SeverityMedium
	case impact >= 0.01:
		return api.SeverityLow
	default:
		// InSpec calls this "none": a control that is informational rather than
		// a control failure worth acting on.
		return api.SeverityInfo
	}
}

// tagsOf flattens a control's tags into the `key:value` strings recon filters
// on, plus the profile that produced it.
//
// A tag's value is free-form — CIS levels are numbers, `nist` is a list, and a
// profile may set a bare marker with no value at all — so each shape becomes
// one or more strings rather than being forced into a single spelling.
func tagsOf(profile Profile, control Control) []string {
	tags := []string{"profile:" + profile.Name}

	keys := make([]string, 0, len(control.Tags))
	for key := range control.Tags {
		keys = append(keys, key)
	}
	// Map order is random and these are stored as an array, so a re-run would
	// otherwise produce a different row for an identical finding.
	sort.Strings(keys)

	for _, key := range keys {
		tags = append(tags, tagValues(key, control.Tags[key])...)
	}
	return tags
}

func tagValues(key string, value any) []string {
	switch typed := value.(type) {
	case nil:
		return []string{key}
	case bool:
		// A false marker is not a tag: filtering on `cis_scored` should find the
		// scored controls, not every control that mentions scoring.
		if !typed {
			return nil
		}
		return []string{key}
	case []any:
		var out []string
		for _, item := range typed {
			out = append(out, tagValues(key, item)...)
		}
		return out
	case string:
		if typed == "" {
			return []string{key}
		}
		return []string{key + ":" + typed}
	case float64:
		return []string{key + ":" + trimFloat(typed)}
	default:
		return []string{fmt.Sprintf("%s:%v", key, typed)}
	}
}

// trimFloat renders a JSON number without the trailing ".0" a %v would give a
// whole number, so `cis_level: 1` tags as `cis_level:1` rather than `cis_level:1e+00`.
func trimFloat(value float64) string {
	if value == float64(int64(value)) {
		return fmt.Sprintf("%d", int64(value))
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", value), "0"), ".")
}

// remediationLabels are the description labels that say how to fix a control,
// in the order they are preferred. Profiles disagree about which they use —
// InSpec's own docs say "fix", the CIS profiles write "remediation" — so both
// are read rather than picking one and silently showing nothing for the other.
var remediationLabels = []string{"fix", "remediation", "rationale"}

func remediation(control Control) string {
	for _, label := range remediationLabels {
		for _, description := range control.Descriptions {
			if strings.EqualFold(description.Label, label) && description.Data != "" {
				return description.Data
			}
		}
	}
	return ""
}

// references collects the citation URLs, keeping profile order and dropping
// duplicates — CIS controls commonly cite the same benchmark page from several
// refs.
func references(control Control) []string {
	var urls []string
	seen := map[string]bool{}
	for _, ref := range control.Refs {
		url := ref.URL
		if url == "" {
			url = ref.URI
		}
		if url == "" {
			url, _ = ref.Ref.(string)
		}
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		urls = append(urls, url)
	}
	return urls
}
