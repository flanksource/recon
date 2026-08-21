package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
)

// runnerFlags are trivy's output contract, owned by recon rather than by a
// profile. They are not in the option catalog, so a profile cannot set them:
// the report is parsed by path and format, and a run that wrote a table to
// stdout would produce no findings at all.
//
// --no-progress because the progress bar is drawn for a terminal and this has
// none; without it the log is megabytes of redrawn bars.
var runnerFlags = []string{"--format", "json", "--no-progress"}

// Run scans every provider context the selector resolved.
//
// One invocation per context: trivy takes a single target, so a selector
// matching three images is three runs whose findings land in one scan. They run
// in sequence — each one pulls an artifact and analyses it, and three at once
// mostly competes for the same bandwidth and the same database.
func (e Engine) Run(ctx context.Context, run engines.Run, sink scan.Sink) (err error) {
	entry, profile, err := profileArguments(run.Config)
	if err != nil {
		return err
	}
	contexts, err := contextsForRun(run.ProviderContexts, entry)
	if err != nil {
		return err
	}

	file, err := os.Create(run.Out)
	if err != nil {
		return fmt.Errorf("create trivy findings: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close trivy findings: %w", closeErr))
		}
	}()

	encoder := json.NewEncoder(file)
	aggregate := newAggregate(len(contexts))
	for _, subject := range contexts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.scanContext(ctx, run, entry, profile, subject, encoder, sink, aggregate); err != nil {
			return err
		}
	}
	return nil
}

// scanContext runs trivy against one context and reports what it found.
func (e Engine) scanContext(
	ctx context.Context,
	run engines.Run,
	entry provider,
	profile map[string]any,
	subject engines.ProviderContext,
	encoder *json.Encoder,
	sink scan.Sink,
	aggregate *aggregate,
) error {
	report := filepath.Join(run.WorkDir, ReportFile(subject.ID))
	argv, err := entry.argv(profile, subject.Arguments, report)
	if err != nil {
		return fmt.Errorf("provider context %s: %w", subject.ID, err)
	}

	invocation := &engines.Invocation{
		Bin:     run.Bin,
		Args:    argv,
		WorkDir: run.WorkDir,
		Stdout:  logWriter{sink: sink},
		Stderr:  logWriter{sink: sink},
	}
	sink.Log("scanning " + subject.ID)
	result := invocation.Run(ctx)

	// The report is read before the exit code is judged: a run cancelled or
	// killed part way still leaves whatever it had written, and discarding that
	// would throw away findings that were genuinely observed.
	found, readErr := readReport(report, subject.ID)
	if found != nil {
		for _, finding := range found.Findings {
			if err := encoder.Encode(finding); err != nil {
				return fmt.Errorf("write trivy finding: %w", err)
			}
			if err := sink.Finding(finding); err != nil {
				return err
			}
		}
		aggregate.add(found)
		sink.Stats(aggregate.snapshot())
	}

	if result.ExitCode != 0 {
		if result.Err != nil {
			return fmt.Errorf("trivy against %s: %w", subject.ID, result.Err)
		}
		return fmt.Errorf("trivy against %s exited %d", subject.ID, result.ExitCode)
	}
	return readErr
}

// Command renders the equivalent command line, for the record kept on the scan.
//
// It describes the first context only. A run over several is several
// invocations differing in one argument, and listing all of them would bury
// what someone actually wants to copy.
func (e Engine) Command(run engines.Run) []string {
	bin := run.Bin
	if bin == "" {
		bin = EngineName
	}
	entry, profile, err := profileArguments(run.Config)
	if err != nil {
		return []string{bin, "<invalid trivy command>"}
	}
	contexts, err := contextsForRun(run.ProviderContexts, entry)
	if err != nil {
		return []string{bin, "<invalid trivy command>"}
	}
	argv, err := entry.argv(profile, contexts[0].Arguments,
		filepath.Join(run.WorkDir, ReportFile(contexts[0].ID)))
	if err != nil {
		return []string{bin, "<invalid trivy command>"}
	}
	return append([]string{bin}, argv...)
}

// profileArguments splits the effective configuration into the provider it
// selects and the options that become flags.
func profileArguments(config map[string]any) (provider, map[string]any, error) {
	id, _ := config["provider"].(string)
	entry, err := find(id)
	if err != nil {
		return provider{}, nil, err
	}

	profile := make(map[string]any, len(config))
	for key, value := range config {
		if key == "provider" {
			continue
		}
		profile[key] = value
	}
	return entry, profile, nil
}

// contextsForRun validates the in-memory subjects against the provider the
// profile selects.
func contextsForRun(subjects []engines.ProviderContext, entry provider) ([]engines.ProviderContext, error) {
	if len(subjects) == 0 {
		return nil, fmt.Errorf("trivy run has no in-memory provider contexts")
	}

	seen := make(map[string]struct{}, len(subjects))
	for _, subject := range subjects {
		switch {
		case subject.ID == "":
			return nil, fmt.Errorf("provider context id is required")
		case subject.Provider != entry.ID:
			return nil, fmt.Errorf("provider context %s uses provider %s, not %s",
				subject.ID, subject.Provider, entry.ID)
		case !subject.CredentialMode.Valid():
			return nil, fmt.Errorf("provider context %s has invalid credential mode %q",
				subject.ID, subject.CredentialMode)
		}
		// Every provider here reads through tooling that resolves its own
		// credentials from the environment, so recon has none to hand over.
		// Refusing rather than ignoring: a context configured with credentials
		// that are never passed is a scan the operator believes is
		// authenticated and is not.
		if subject.Credentials != nil && !subject.Credentials.Empty() {
			return nil, fmt.Errorf(
				"provider context %s carries credentials, which trivy does not accept: "+
					"registry, cloud and git credentials are read from the environment recon runs in",
				subject.ID)
		}
		if _, found := seen[subject.ID]; found {
			return nil, fmt.Errorf("duplicate provider context %q", subject.ID)
		}
		seen[subject.ID] = struct{}{}
	}
	return subjects, nil
}

// argv builds one invocation's command line.
//
// Order is subcommand, then the profile's flags, then the context's, then
// recon's own, then the positional subject. Deterministic within each group so
// a recorded command is diffable rather than reordering per run.
func (p provider) argv(profile, arguments map[string]any, report string) ([]string, error) {
	subject, err := p.subject(arguments)
	if err != nil {
		return nil, err
	}

	argv := []string{p.Command}
	argv = append(argv, flags(profile)...)

	// The subject is positional, so it is not also a flag.
	scope := make(map[string]any, len(arguments))
	for key, value := range arguments {
		if key != p.Subject {
			scope[key] = value
		}
	}
	argv = append(argv, flags(scope)...)

	argv = append(argv, runnerFlags...)
	argv = append(argv, "--output", report)
	return append(argv, subject), nil
}

// subject reads the positional argument out of the context.
func (p provider) subject(arguments map[string]any) (string, error) {
	value, _ := arguments[p.Subject].(string)
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required: there is nothing to scan", p.Subject)
	}
	if p.ID == ProviderFilesystem && !filepath.IsAbs(value) {
		return "", fmt.Errorf(
			"%s %q is relative: a scan runs from its own artifact directory, so it would "+
				"resolve against nothing", p.Subject, value)
	}
	return value, nil
}

// flags renders configuration as trivy's own long flags.
//
// Trivy's list flags are comma-separated rather than repeated, and a false
// boolean means "leave the default alone" rather than "--flag=false", so this
// cannot be engines.ConfigArgs — which writes single-dash flags and repeats a
// list.
func flags(config map[string]any) []string {
	keys := make([]string, 0, len(config))
	for key := range config {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var argv []string
	for _, key := range keys {
		argv = append(argv, flag(key, config[key])...)
	}
	return argv
}

func flag(key string, value any) []string {
	name := "--" + key

	switch typed := value.(type) {
	case nil:
		return nil
	case bool:
		if !typed {
			return nil
		}
		return []string{name}
	case string:
		if typed == "" {
			return nil
		}
		return []string{name, typed}
	}

	if list, ok := asList(value); ok {
		list = compact(list)
		if len(list) == 0 {
			return nil
		}
		return []string{name, strings.Join(list, ",")}
	}
	if number, ok := asNumber(value); ok {
		return []string{name, formatNumber(number)}
	}
	return []string{name, fmt.Sprint(value)}
}

func formatNumber(value float64) string {
	if value == float64(int64(value)) {
		return strconv.FormatInt(int64(value), 10)
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

// asList accepts both JSON's []any and a Go literal's []string, because a
// profile arrives decoded from jsonb in one case and written in Go in the other.
func asList(value any) ([]string, bool) {
	switch typed := value.(type) {
	case []string:
		return typed, true
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if item == nil {
				continue
			}
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, text)
		}
		return out, true
	}
	return nil, false
}

func stringList(value any) []string {
	list, _ := asList(value)
	return list
}

// asNumber accepts every numeric shape a YAML or JSON decoder produces.
func asNumber(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	}
	return 0, false
}

// aggregate accumulates the counts across every context in one run.
type aggregate struct {
	stats               api.ScanStats
	artifacts           map[string]struct{}
	templates           map[string]struct{}
	completed, contexts int
}

func newAggregate(contexts int) *aggregate {
	return &aggregate{
		artifacts: map[string]struct{}{},
		templates: map[string]struct{}{},
		contexts:  contexts,
	}
}

func (a *aggregate) add(report *parsed) {
	stats := report.Stats()
	a.stats.Requests += stats.Requests
	a.stats.Total += stats.Total
	a.stats.Matched += stats.Matched
	if report.Artifact != "" {
		a.artifacts[report.Artifact] = struct{}{}
	}
	for template := range report.templates {
		a.templates[template] = struct{}{}
	}
	a.completed++
}

func (a *aggregate) snapshot() api.ScanStats {
	stats := a.stats
	stats.Hosts = float64(len(a.artifacts))
	stats.Templates = float64(len(a.templates))
	stats.Percent = float64(a.completed) / float64(a.contexts) * 100
	return stats
}

// logWriter forwards process output to the sink as it arrives, so a scan that
// takes minutes shows progress rather than nothing.
type logWriter struct{ sink scan.Sink }

func (w logWriter) Write(p []byte) (int, error) {
	if text := strings.TrimRight(string(p), "\n"); text != "" {
		w.sink.Log(text)
	}
	return len(p), nil
}
