// Command gen-playground-fixture builds the recon design fixture for the
// clicky-ui playground.
//
//	go run ./hack/gen-playground-fixture \
//	    --out ../clicky-ui/apps/playground/src/pages/_recon
//
// The playground pages under `pages/recon/*` argue for surfaces recon does not
// have yet — a findings list that is not nested inside one run, and a cloud
// resource inventory that does not exist as an entity at all. An argument made
// against invented data is worthless, so every check id, title, severity,
// service, resource type, category, description, risk, remediation and
// compliance requirement below is copied verbatim from the pinned Prowler
// catalogue that recon already embeds. Only the things that would name live
// infrastructure — accounts, resource names, ARNs — are placeholders, because
// the playground lives in a public repository.
//
// The findings are assembled by the same rules the real ingest uses. Tag
// emission mirrors recordTags in internal/engines/scan/prowler/ocsf.go exactly:
// change one and this generator has to change with it, which is the point of
// generating rather than hand-writing 600 records.
//
// Output is deterministic — no clock, no map iteration, no randomness beyond a
// seeded PRNG — so re-running it produces a byte-identical tree and a diff
// means the catalogue moved.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/flanksource/recon/internal/engines/scan/prowler/catalog"
)

func main() {
	out := flag.String("out", "", "directory to write the fixture into (required)")
	flag.Parse()
	if *out == "" {
		fatal(fmt.Errorf("--out is required"))
	}
	if err := run(*out); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "gen-playground-fixture:", err)
	os.Exit(1)
}

func run(out string) error {
	loaded, err := catalog.Embedded()
	if err != nil {
		return fmt.Errorf("load embedded catalogue: %w", err)
	}

	compliance := complianceIndex(loaded)
	checks, err := selectChecks(loaded)
	if err != nil {
		return err
	}

	resources := buildResources(checks)
	findings := buildFindings(checks, resources)
	runs := buildRuns(findings, checks)

	if err := os.MkdirAll(out, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", out, err)
	}
	for name, payload := range map[string]any{
		"catalog.json":  checkRecords(checks, compliance),
		"findings.json": findings,
		"runs.json":     runs,
	} {
		if err := writeJSON(filepath.Join(out, name), payload); err != nil {
			return err
		}
	}

	fmt.Printf("%d checks, %d resources, %d findings, %d runs -> %s\n",
		len(checks), len(resources), len(findings), len(runs), out)
	return nil
}

func writeJSON(path string, payload any) error {
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// complianceIndex reverses the catalogue's profile->control->check nesting into
// the check->requirements direction a finding needs.
//
// The framework key is built the way Prowler's own get_check_compliance does:
// the framework name, plus "-<version>" when the profile carries one. That is
// what produces the awkward real values the UI has to survive — "CIS-4.0.1",
// but also "DORA-2022/2554" with a slash and "ASD-Essential-Eight-Nov 2023"
// with a space.
func complianceIndex(loaded *catalog.Catalog) map[string][]string {
	index := map[string]map[string]struct{}{}
	for _, profile := range loaded.Profiles {
		framework := profile.Framework
		if profile.Version != "" {
			framework += "-" + profile.Version
		}
		for _, control := range profile.Controls {
			requirement := framework + ":" + control.ID
			for _, key := range control.CheckKeys {
				if index[key] == nil {
					index[key] = map[string]struct{}{}
				}
				index[key][requirement] = struct{}{}
			}
		}
	}

	out := make(map[string][]string, len(index))
	for key, set := range index {
		requirements := make([]string, 0, len(set))
		for requirement := range set {
			requirements = append(requirements, requirement)
		}
		sort.Strings(requirements)
		out[key] = requirements
	}
	return out
}

// account is a placeholder cloud account. acme-sandbox carries no findings on
// purpose: the resources dashboard has to be able to say "scanned and clean" is
// not something recon can currently distinguish from "never scanned", and that
// needs an account with nothing in it.
type account struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	UID      string `json:"uid"`
	Provider string `json:"provider"`
	Regions  []string
}

var accounts = []account{
	{ID: "acme-prod", Name: "acme-prod", UID: "012345678901", Provider: "aws",
		Regions: []string{"us-east-1", "eu-west-1", "ap-southeast-2"}},
	{ID: "acme-staging", Name: "acme-staging", UID: "012345678902", Provider: "aws",
		Regions: []string{"us-east-1", "eu-west-1"}},
	{ID: "acme-sandbox", Name: "acme-sandbox", UID: "012345678903", Provider: "aws",
		Regions: []string{"us-east-1"}},
	{ID: "acme-platform", Name: "acme-platform", UID: "acme-platform", Provider: "gcp",
		Regions: []string{"europe-west1", "us-central1"}},
	{ID: "acme-corp-eu", Name: "acme-corp-eu", UID: "00000000-0000-0000-0000-000000000001", Provider: "azure",
		Regions: []string{"westeurope", "northeurope"}},
	{ID: "acme-eks-prod", Name: "acme-eks-prod", UID: "acme-eks-prod", Provider: "kubernetes",
		Regions: nil},
}

// wanted describes how many findings each provider contributes and which
// services they come from. The service lists track the catalogue's own
// top-services ranking so the fixture's shape is the real shape: ec2 and iam
// dominate AWS because they really do carry the most checks.
var wanted = []struct {
	provider string
	findings int
	services []string
}{
	{"aws", 380, []string{"ec2", "iam", "s3", "rds", "cloudwatch", "cloudtrail", "awslambda", "elbv2", "cloudfront", "kms"}},
	{"azure", 90, []string{"storage", "defender", "entra", "sqlserver", "monitor"}},
	{"gcp", 80, []string{"iam", "compute", "cloudstorage", "cloudsql", "logging"}},
	{"kubernetes", 70, []string{"rbac", "apiserver", "kubelet", "etcd"}},
}

// selectChecks picks the catalogue checks the fixture is built from.
//
// It takes a spread across every severity a service offers rather than the most
// severe few. Sorting by severity and taking the head would produce a
// critical-heavy corpus, and the real catalogue is the opposite shape: AWS is
// 63 critical against 315 medium. That long medium tail is the thing the triage
// treatments have to cope with, so a fixture that flatters them by omitting it
// would be arguing against a problem nobody has.
func selectChecks(loaded *catalog.Catalog) ([]catalog.Check, error) {
	byProviderService := map[string][]catalog.Check{}
	for _, check := range loaded.Checks {
		key := check.Provider + "/" + check.Service
		byProviderService[key] = append(byProviderService[key], check)
	}

	var selected []catalog.Check
	for _, group := range wanted {
		for _, service := range group.services {
			candidates := byProviderService[group.provider+"/"+service]
			if len(candidates) == 0 {
				return nil, fmt.Errorf("catalogue has no %s/%s checks", group.provider, service)
			}
			selected = append(selected, spread(candidates, 2)...)
		}
	}

	sort.Slice(selected, func(i, j int) bool { return selected[i].Key < selected[j].Key })
	return selected, nil
}

// spread takes up to `perSeverity` checks at each severity level a service
// offers, preferring the ones that ship a remediation snippet since the
// finding-detail page exists to argue for rendering it.
func spread(candidates []catalog.Check, perSeverity int) []catalog.Check {
	bySeverity := map[string][]catalog.Check{}
	for _, check := range candidates {
		level := prowlerSeverity(check.Severity)
		bySeverity[level] = append(bySeverity[level], check)
	}

	var out []catalog.Check
	for _, level := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		pool := bySeverity[level]
		if len(pool) == 0 {
			continue
		}
		sort.Slice(pool, func(i, j int) bool {
			if hasCode(pool[i]) != hasCode(pool[j]) {
				return hasCode(pool[i])
			}
			return pool[i].Key < pool[j].Key
		})
		take := perSeverity
		if len(pool) < take {
			take = len(pool)
		}
		out = append(out, pool[:take]...)
	}
	return out
}

func hasCode(check catalog.Check) bool {
	for _, value := range check.Remediation.Code {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

var severityOrder = []string{"critical", "high", "medium", "low", "informational", "unknown"}

func severityRank(value string) int {
	for rank, name := range severityOrder {
		if strings.EqualFold(value, name) {
			return rank
		}
	}
	return len(severityOrder)
}

// prowlerSeverity mirrors internal/engines/scan/prowler/ocsf.go: Prowler says
// "informational", recon's wire type says "info".
func prowlerSeverity(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "informational" {
		return "info"
	}
	if severityRank(value) == len(severityOrder) {
		return "unknown"
	}
	return value
}

// resource is a placeholder cloud resource. Names are invented; types are the
// catalogue's real ResourceType values, because the resource pages group by
// them and an invented type would make those groupings meaningless.
type resource struct {
	UID       string
	Name      string
	Type      string
	Service   string
	Region    string
	Namespace string
	Account   account
}

var nouns = []string{
	"audit-logs", "payments-api", "checkout", "artifacts", "billing", "customer-data",
	"analytics-raw", "sessions", "invoices", "ledger", "search-index", "media",
	"backups", "reporting", "notifications", "identity", "gateway", "warehouse",
}

// buildResources invents a resource population for the selected checks. Roughly
// a fifth of the catalogue's AWS checks name no real resource type, so the
// "Other" case is not an edge case to hide — it is a fifth of the inventory,
// and the resource pages have to show it as untyped rather than dropping it.
func buildResources(checks []catalog.Check) []resource {
	random := rand.New(rand.NewSource(20240822))
	byKey := map[string]resource{}
	var ordered []resource

	for _, check := range checks {
		hosts := candidateAccounts(check.Provider)
		count := 1 + random.Intn(3)
		for i := 0; i < count; i++ {
			host := hosts[random.Intn(len(hosts))]
			noun := nouns[random.Intn(len(nouns))]
			res := makeResource(check, host, noun, random)
			if _, seen := byKey[res.Account.ID+"|"+res.UID]; seen {
				continue
			}
			byKey[res.Account.ID+"|"+res.UID] = res
			ordered = append(ordered, res)
		}
	}

	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Account.ID != ordered[j].Account.ID {
			return ordered[i].Account.ID < ordered[j].Account.ID
		}
		return ordered[i].UID < ordered[j].UID
	})
	return ordered
}

func candidateAccounts(provider string) []account {
	var hosts []account
	for _, candidate := range accounts {
		if candidate.Provider != provider || candidate.ID == "acme-sandbox" {
			continue
		}
		hosts = append(hosts, candidate)
	}
	if len(hosts) == 0 {
		return []account{accounts[0]}
	}
	return hosts
}

func makeResource(check catalog.Check, host account, noun string, random *rand.Rand) resource {
	res := resource{
		Name:    "acme-" + noun,
		Type:    check.ResourceType,
		Service: check.Service,
		Account: host,
	}
	if len(host.Regions) > 0 {
		res.Region = host.Regions[random.Intn(len(host.Regions))]
	}

	switch host.Provider {
	case "aws":
		// IAM is a global service: its findings carry no region, which is why
		// a region column cannot be assumed present.
		if check.Service == "iam" {
			res.Region = ""
		}
		res.UID = fmt.Sprintf("arn:aws:%s:%s:%s:%s/%s",
			check.Service, res.Region, host.UID, strings.ToLower(shortType(check.ResourceType)), res.Name)
	case "gcp":
		res.UID = fmt.Sprintf("projects/%s/%s/%s", host.UID, check.Service, res.Name)
	case "azure":
		res.UID = fmt.Sprintf("/subscriptions/%s/resourceGroups/acme-rg/providers/Microsoft.%s/%s",
			host.UID, strings.Title(check.Service), res.Name) //nolint:staticcheck // ASCII service names only
	case "kubernetes":
		// Kubernetes has no region. Prowler puts a namespace where a region
		// would go, so a UI that assumes "region" is universal renders a blank
		// column for every kubernetes row.
		res.Region = ""
		res.Namespace = "kube-system"
		res.UID = fmt.Sprintf("%s/%s", res.Namespace, res.Name)
	}
	return res
}

func shortType(resourceType string) string {
	if resourceType == "" || strings.EqualFold(resourceType, "Other") {
		return "resource"
	}
	parts := strings.Split(resourceType, "::")
	return parts[len(parts)-1]
}

// finding is the per-instance half of api.Finding — everything that varies
// between two findings of the same check.
//
// The wire type is much fatter than this: it repeats the check's title,
// severity, remediation, references and its thirty-to-two-hundred compliance
// tags on every single row. That repetition is real and the pages have to
// reckon with it, but committing it 620 times would put three megabytes of
// duplicated strings in a public repo for no gain. `fixture.ts` rehydrates the
// full wire shape by joining `checkKey` against catalog.json, so a page still
// sees exactly what `GET /api/v1/finding` returns.
type finding struct {
	ScanID      string         `json:"scanId"`
	LineNo      int            `json:"lineNo"`
	TargetID    string         `json:"targetId"`
	CheckKey    string         `json:"checkKey"`
	Host        string         `json:"host"`
	MatchedAt   string         `json:"matchedAt"`
	MatcherName string         `json:"matcherName"`
	Timestamp   string         `json:"timestamp"`
	Resource    map[string]any `json:"resource"`
	Account     map[string]any `json:"account"`
}

// runDays are the scan dates, oldest first. Fixed rather than derived from the
// clock so the fixture does not change under a reader.
var runDays = []string{
	"2026-07-13", "2026-07-20", "2026-07-27", "2026-08-03",
	"2026-08-10", "2026-08-14", "2026-08-18", "2026-08-21",
}

// severityMix is the shape the corpus targets, in the catalogue's own
// proportions: a small critical head and a long medium tail. Drawing the
// severity first and then picking a check that carries it keeps the corpus
// honest regardless of which checks happened to be selected.
var severityMix = []struct {
	level  string
	weight int
}{
	{"critical", 34},
	{"high", 168},
	{"medium", 310},
	{"low", 96},
	{"info", 12},
}

func buildFindings(checks []catalog.Check, resources []resource) []finding {
	random := rand.New(rand.NewSource(19770521))
	byProvider := map[string][]resource{}
	for _, res := range resources {
		byProvider[res.Account.Provider] = append(byProvider[res.Account.Provider], res)
	}
	pools := map[string][]catalog.Check{}
	for _, check := range checks {
		key := check.Provider + "|" + prowlerSeverity(check.Severity)
		pools[key] = append(pools[key], check)
	}

	latest := runDays[len(runDays)-1]
	scanID := "scan-" + strings.ReplaceAll(latest, "-", "")
	var out []finding

	total := 0
	for _, group := range wanted {
		total += group.findings
	}

	for _, group := range wanted {
		hosts := byProvider[group.provider]
		if len(hosts) == 0 {
			continue
		}
		for i := 0; i < group.findings; i++ {
			check, ok := drawCheck(pools, group.provider, random, total)
			if !ok {
				continue
			}
			candidates := matching(hosts, check)
			res := candidates[random.Intn(len(candidates))]

			// MANUAL is a real third verdict, not a failure. A UI that paints
			// it red tells someone to fix what a human has to go and read.
			matcher := "FAIL"
			if random.Intn(20) == 0 {
				matcher = "MANUAL"
			}
			out = append(out, finding{
				TargetID:    res.Account.ID,
				CheckKey:    check.Key,
				Host:        res.Account.Name,
				MatchedAt:   res.UID,
				MatcherName: matcher,
				Timestamp:   latest + "T04:1" + fmt.Sprint(i%10) + ":00Z",
				Resource:    resourceEntry(res),
				Account:     map[string]any{"name": res.Account.Name, "uid": res.Account.UID},
			})
		}
	}

	// Order is the engine's print order, which is what the API returns and what
	// makes `limit` drop an arbitrary tail rather than the least severe rows.
	for i := range out {
		out[i].ScanID = scanID
		out[i].LineNo = i + 1
	}
	return out
}

// drawCheck picks a severity from the target mix, then a check of that severity
// for the provider. It falls back through the remaining levels when a provider
// has nothing at the drawn one — kubernetes has no critical checks at all, and
// silently emitting a wrong severity would be worse than picking a near one.
func drawCheck(pools map[string][]catalog.Check, provider string, random *rand.Rand, total int) (catalog.Check, bool) {
	roll := random.Intn(total)
	level := severityMix[len(severityMix)-1].level
	for _, entry := range severityMix {
		if roll < entry.weight {
			level = entry.level
			break
		}
		roll -= entry.weight
	}

	order := append([]string{level}, "medium", "high", "low", "critical", "info")
	for _, candidate := range order {
		if pool := pools[provider+"|"+candidate]; len(pool) > 0 {
			return pool[random.Intn(len(pool))], true
		}
	}
	return catalog.Check{}, false
}

func matching(hosts []resource, check catalog.Check) []resource {
	var candidates []resource
	for _, host := range hosts {
		if host.Service == check.Service {
			candidates = append(candidates, host)
		}
	}
	if len(candidates) == 0 {
		return hosts
	}
	return candidates
}

// resourceEntry reproduces one element of Prowler's OCSF `resources` array.
// recon keeps that blob verbatim, and it is the only place a resource's region
// survives — the Go struct that parses the record does not decode that field,
// so region reaches no column and no filter today.
func resourceEntry(res resource) map[string]any {
	entry := map[string]any{
		"name":   res.Name,
		"uid":    res.UID,
		"type":   res.Type,
		"group":  map[string]any{"name": res.Service},
		"labels": []string{"owner:platform", "env:" + envOf(res.Account.ID)},
	}
	if res.Region != "" {
		entry["region"] = res.Region
	}
	// Kubernetes has no region; Prowler puts a namespace where one would go.
	if res.Namespace != "" {
		entry["namespace"] = res.Namespace
	}
	return entry
}

func envOf(accountID string) string {
	switch {
	case strings.Contains(accountID, "prod"):
		return "production"
	case strings.Contains(accountID, "staging"):
		return "staging"
	default:
		return "sandbox"
	}
}

// scan mirrors the fields of api.Scan the trend views read. severities is
// denormalised onto the row in the real schema, which is why a per-run severity
// trend is the one aggregate recon can serve today without new work.
type scan struct {
	ID         string         `json:"id"`
	Engine     string         `json:"engine"`
	Profile    string         `json:"profile"`
	Phase      string         `json:"phase"`
	Start      string         `json:"start"`
	Findings   int            `json:"findings"`
	Muted      int            `json:"muted"`
	Severities map[string]int `json:"severities"`
}

// buildRuns gives the latest run the real severity mix of the findings above
// and walks the earlier runs back from it, so the trend is consistent with the
// corpus rather than an unrelated series.
func buildRuns(findings []finding, checks []catalog.Check) []scan {
	severityOf := map[string]string{}
	for _, check := range checks {
		severityOf[check.Key] = prowlerSeverity(check.Severity)
	}
	latest := map[string]int{}
	for _, item := range findings {
		latest[severityOf[item.CheckKey]]++
	}

	random := rand.New(rand.NewSource(31415926))
	runs := make([]scan, 0, len(runDays))
	for index, day := range runDays {
		severities := map[string]int{}
		total := 0
		// Earlier runs drift away from the latest mix; the last run is exact.
		drift := float64(len(runDays)-1-index) * 0.06
		for _, level := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
			count := latest[level]
			if drift > 0 {
				count = int(float64(count) * (1 + drift - random.Float64()*drift/2))
			}
			severities[level] = count
			total += count
		}
		runs = append(runs, scan{
			ID:         "scan-" + strings.ReplaceAll(day, "-", ""),
			Engine:     "prowler",
			Profile:    "aws-cis-4-0-aws",
			Phase:      "done",
			Start:      day + "T04:00:00Z",
			Findings:   total,
			Muted:      random.Intn(9),
			Severities: severities,
		})
	}
	return runs
}

// checkRecord is the catalogue subset the playground ships. Everything here is
// upstream Prowler content, reproduced verbatim.
type checkRecord struct {
	Key          string            `json:"key"`
	ID           string            `json:"id"`
	Provider     string            `json:"provider"`
	Title        string            `json:"title"`
	Severity     string            `json:"severity"`
	Service      string            `json:"service"`
	ResourceType string            `json:"resourceType"`
	Categories   []string          `json:"categories"`
	Description  string            `json:"description"`
	Risk         string            `json:"risk"`
	Remediation  string            `json:"remediation"`
	RemediationC map[string]string `json:"remediationCode,omitempty"`
	References   []string          `json:"references"`
	Compliance   []string          `json:"compliance"`
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func checkRecords(checks []catalog.Check, compliance map[string][]string) []checkRecord {
	records := make([]checkRecord, 0, len(checks))
	for _, check := range checks {
		code := map[string]string{}
		for flavour, snippet := range check.Remediation.Code {
			if strings.TrimSpace(snippet) != "" {
				code[flavour] = snippet
			}
		}
		records = append(records, checkRecord{
			Key:          check.Key,
			ID:           check.ID,
			Provider:     check.Provider,
			Title:        check.Title,
			Severity:     prowlerSeverity(check.Severity),
			Service:      check.Service,
			ResourceType: check.ResourceType,
			// Always an array, never null. recon's own API makes the same
			// guarantee for Tags and Profiles, and for the same reason: a
			// consumer that has to null-check every list will eventually
			// forget one.
			Categories:   nonNil(check.Categories),
			Description:  check.Description,
			Risk:         check.Risk,
			Remediation:  check.Remediation.Text,
			RemediationC: code,
			References:   nonNil(check.References),
			Compliance:   nonNil(compliance[check.Key]),
		})
	}
	return records
}
