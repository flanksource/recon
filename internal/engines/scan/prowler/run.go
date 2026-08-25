package prowler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
	"github.com/flanksource/recon/internal/engines/scan/prowler/arguments"
	"github.com/flanksource/recon/internal/engines/scan/prowler/auth"
)

const outputDirectory = "output"

var runnerArguments = map[string]any{
	"output-directory": outputDirectory,
	"no-banner":        true,
	"no-color":         true,
}

func (e Engine) Run(ctx context.Context, run engines.Run, sink scan.Sink) (err error) {
	catalogue, err := e.argumentCatalogue()
	if err != nil {
		return err
	}
	provider, profile, err := profileArguments(run.Config, catalogue)
	if err != nil {
		return err
	}
	contexts, err := providerContextsForRun(run.ProviderContexts, provider)
	if err != nil {
		return err
	}
	findings, err := os.Create(run.Out)
	if err != nil {
		return fmt.Errorf("create prowler findings: %w", err)
	}
	defer func() {
		if closeErr := findings.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close prowler findings: %w", closeErr))
		}
	}()

	encoder := json.NewEncoder(findings)
	aggregate := newAggregateStats(len(contexts))
	for index, subject := range contexts {
		if err := ctx.Err(); err != nil {
			return err
		}
		input := auditInput{
			Run: run, Subject: subject, Index: index,
			Provider: provider, Profile: profile, Catalogue: catalogue,
		}
		if err := e.audit(ctx, input, encoder, sink, aggregate); err != nil {
			return err
		}
	}
	return nil
}

// Command records the first context invocation, with credential selectors and
// runner-owned paths redacted by the same generated policy used for live logs.
func (e Engine) Command(run engines.Run) []string {
	bin := run.Bin
	if bin == "" {
		bin = EngineName
	}
	catalogue, err := e.argumentCatalogue()
	if err != nil {
		return []string{bin, "<invalid Prowler command>"}
	}
	provider, profile, err := profileArguments(run.Config, catalogue)
	if err != nil {
		return []string{bin, "<invalid Prowler command>"}
	}
	contexts, err := providerContextsForRun(run.ProviderContexts, provider)
	if err != nil || len(contexts) == 0 {
		return []string{bin, "<invalid Prowler command>"}
	}
	if err := e.validateProviderCredentials(provider, contexts[0]); err != nil {
		return []string{bin, "<invalid Prowler command>"}
	}
	_, safe, err := buildArgv(catalogue, provider, profile, contexts[0])
	if err != nil {
		return []string{bin, "<invalid Prowler command>"}
	}
	return append([]string{bin}, safe...)
}

type auditInput struct {
	Run       engines.Run
	Subject   providerContext
	Index     int
	Provider  string
	Profile   map[string]any
	Catalogue *arguments.Catalogue
}

func (e Engine) audit(
	ctx context.Context,
	input auditInput,
	encoder *json.Encoder,
	sink scan.Sink,
	aggregate *aggregateStats,
) error {
	workDir := filepath.Join(input.Run.WorkDir, "contexts", fmt.Sprintf("%04d", input.Index+1))
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return fmt.Errorf("create Prowler context directory: %w", err)
	}
	if err := e.validateProviderCredentials(input.Provider, input.Subject); err != nil {
		return err
	}
	argv, safe, err := buildArgv(input.Catalogue, input.Provider, input.Profile, input.Subject)
	if err != nil {
		return fmt.Errorf("provider context %s: %w", input.Subject.ID, err)
	}
	sink.Log("running " + strings.Join(append([]string{input.Run.Bin}, safe...), " "))
	logs := newRedactingLogWriter(sink, redactedValues(argv, safe))
	result, runErr := executeProviderContext(ctx, input.Run, input.Subject, workDir, argv, safe, logs)
	logs.Close()

	reportPath, findErr := findOCSFReport(filepath.Join(workDir, outputDirectory))
	if findErr == nil {
		report, readErr := readOCSF(reportPath, input.Subject.ID, input.Provider)
		if readErr != nil {
			return readErr
		}
		if err := emitReport(report, encoder, sink); err != nil {
			return err
		}
		aggregate.add(report)
		aggregate.completed++
		sink.Stats(aggregate.snapshot())
	}
	if runErr != nil {
		if result != nil {
			return fmt.Errorf("prowler context %s exited %d: %w", input.Subject.ID, result.ExitCode, runErr)
		}
		return fmt.Errorf("prowler context %s: %w", input.Subject.ID, runErr)
	}
	if result == nil {
		return fmt.Errorf("prowler context %s returned no execution result", input.Subject.ID)
	}
	if !ranToCompletion(result.ExitCode) {
		return fmt.Errorf("prowler context %s exited %d", input.Subject.ID, result.ExitCode)
	}
	if findErr != nil {
		return findErr
	}
	return nil
}

func profileArguments(config map[string]any, catalogue *arguments.Catalogue) (string, map[string]any, error) {
	provider, ok := config["provider"].(string)
	if !ok || provider == "" {
		return "", nil, fmt.Errorf("prowler profile provider is required")
	}
	profile := make(map[string]any, len(config)-1)
	for key, value := range config {
		if key != "provider" {
			profile[key] = value
		}
	}
	if err := catalogue.RejectSensitive(provider, profile); err != nil {
		return "", nil, err
	}
	if err := requireOCSF(profile); err != nil {
		return "", nil, err
	}
	return provider, profile, nil
}

func requireOCSF(profile map[string]any) error {
	value, configured := profile["output-formats"]
	if !configured {
		return nil
	}
	formats, ok := stringSlice(value)
	if !ok {
		return fmt.Errorf("output-formats must be a string array")
	}
	for _, format := range formats {
		if format == "json-ocsf" {
			return nil
		}
	}
	return fmt.Errorf("output-formats must include json-ocsf")
}

func buildArgv(
	catalogue *arguments.Catalogue,
	provider string,
	profile map[string]any,
	subject providerContext,
) ([]string, []string, error) {
	var method *auth.Method
	if subject.CredentialMode == api.CredentialConfigured {
		credentials, err := credentialMap(subject.Credentials)
		if err != nil {
			return nil, nil, err
		}
		matched, err := auth.Match(provider, subject.Arguments, credentials)
		if err != nil {
			return nil, nil, err
		}
		method = &matched
	}
	contextArguments, err := auth.ProjectArguments(provider, subject.Arguments, method)
	if err != nil {
		return nil, nil, err
	}
	if err := catalogue.RejectSensitive(provider, contextArguments); err != nil {
		return nil, nil, err
	}
	if _, err := mergeContextInputs(profile, contextArguments); err != nil {
		return nil, nil, err
	}
	partitioned, err := catalogue.PartitionProviderContext(
		provider, contextArguments, arguments.ProviderContextOptions{
			Mode:               arguments.CredentialMode(subject.CredentialMode),
			RuntimeCredentials: subject.Credentials != nil && !subject.Credentials.Empty(),
		})
	if err != nil {
		return nil, nil, err
	}
	partitioned.Profile = profile
	partitioned.Runner = runnerArguments
	argv, err := catalogue.BuildArgv(provider, partitioned)
	if err != nil {
		return nil, nil, err
	}
	safe, err := catalogue.RedactArgv(provider, argv)
	return argv, safe, err
}

func emitReport(report ocsfReport, encoder *json.Encoder, sink scan.Sink) error {
	for _, finding := range report.Findings {
		if err := encoder.Encode(finding); err != nil {
			return fmt.Errorf("write Prowler finding: %w", err)
		}
		if err := sink.Finding(finding); err != nil {
			return err
		}
	}
	// Every subject the report named, including the ones every check passed on.
	// They are not written to the findings file: that file is the engine's own
	// results and a resource is not a result.
	for _, resource := range report.Resources() {
		if err := sink.Resource(resource); err != nil {
			return err
		}
	}
	return nil
}

func findOCSFReport(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read Prowler output directory: %w", err)
	}
	paths := []string{}
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".ocsf.json") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	sort.Strings(paths)
	if len(paths) != 1 {
		return "", fmt.Errorf("prowler output must contain exactly one top-level OCSF report, found %d", len(paths))
	}
	return paths[0], nil
}

func ranToCompletion(code int) bool { return code == 0 || code == 3 }

type aggregateStats struct {
	stats               api.ScanStats
	hosts, templates    map[string]struct{}
	completed, contexts int
}

func newAggregateStats(contexts int) *aggregateStats {
	return &aggregateStats{hosts: map[string]struct{}{}, templates: map[string]struct{}{}, contexts: contexts}
}

func (a *aggregateStats) add(report ocsfReport) {
	a.stats.Requests += report.Stats.Requests
	a.stats.Total += report.Stats.Total
	a.stats.Matched += report.Stats.Matched
	a.stats.Errors += report.Stats.Errors
	a.stats.Passed += report.Stats.Passed
	a.stats.PassRecorded = a.stats.PassRecorded || report.Stats.PassRecorded
	for host := range report.hosts {
		a.hosts[host] = struct{}{}
	}
	for template := range report.templates {
		a.templates[template] = struct{}{}
	}
}

func (a *aggregateStats) snapshot() api.ScanStats {
	stats := a.stats
	stats.Hosts = float64(len(a.hosts))
	stats.Templates = float64(len(a.templates))
	stats.Percent = float64(a.completed) / float64(a.contexts) * 100
	return stats
}

func stringSlice(value any) ([]string, bool) {
	switch values := value.(type) {
	case []string:
		return values, true
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	default:
		return nil, false
	}
}

func redactedValues(argv, safe []string) []string {
	values := []string{}
	for index := range min(len(argv), len(safe)) {
		if argv[index] != safe[index] {
			values = append(values, argv[index])
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	return values
}

type redactingLogWriter struct {
	mu      sync.Mutex
	sink    scan.Sink
	values  []string
	pending string
}

func newRedactingLogWriter(sink scan.Sink, values []string) *redactingLogWriter {
	return &redactingLogWriter{sink: sink, values: values}
}

func (w *redactingLogWriter) AddSensitive(values []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, value := range values {
		if value != "" {
			w.values = append(w.values, value)
		}
	}
	sort.Slice(w.values, func(i, j int) bool { return len(w.values[i]) > len(w.values[j]) })
}

func (w *redactingLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending += string(p)
	for {
		line, rest, found := strings.Cut(w.pending, "\n")
		if !found {
			return len(p), nil
		}
		w.sink.Log(w.redact(line))
		w.pending = rest
	}
}

func (w *redactingLogWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending != "" {
		w.sink.Log(w.redact(w.pending))
		w.pending = ""
	}
}

func (w *redactingLogWriter) redact(value string) string {
	for _, sensitive := range w.values {
		value = strings.ReplaceAll(value, sensitive, arguments.RedactedValue)
	}
	return value
}

var _ io.Writer = (*redactingLogWriter)(nil)
