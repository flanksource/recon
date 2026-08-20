package inspec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
)

// InputsFile is the generated input file handed to each invocation.
const InputsFile = "inputs.yml"

// ReportFile names the retained exec-json for one account. Per account rather
// than one merged document, because that is the shape the tool produced and
// what someone re-running it by hand would get back.
func ReportFile(account string) string { return "inspec-" + account + ".json" }

// Exit codes InSpec uses. 100 and 101 are outcomes, not failures: a benchmark
// that finds nothing wrong and one that finds a hundred things both ran
// correctly, and treating a control failure as a run failure would report every
// non-compliant account as a broken scan.
const (
	exitAllPassed = 0
	exitFailed    = 100
	exitSkipped   = 101
)

// Run audits every account in the input list.
//
// One invocation per account: InSpec's `-t` takes a single target, so a
// selector matching three projects is three runs whose findings land in one
// scan. They run in sequence rather than concurrently — the benchmarks are API
// rate-limit bound, and three at once mostly buys throttling.
func (e Engine) Run(ctx context.Context, run engines.Run, sink scan.Sink) error {
	accounts, err := readAccounts(run.In)
	if err != nil {
		return err
	}

	if limit := timeLimit(run.Config); limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}

	inputs, err := writeInputs(run)
	if err != nil {
		return err
	}

	findings, err := os.Create(run.Out)
	if err != nil {
		return fmt.Errorf("create findings file: %w", err)
	}
	defer func() { _ = findings.Close() }()
	encoder := json.NewEncoder(findings)

	progress := newProgress(sink, len(accounts))
	for _, account := range accounts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.audit(ctx, run, account, inputs, encoder, sink, progress); err != nil {
			return err
		}
	}
	progress.done()
	return nil
}

// audit runs the benchmark against one account and reports what it found.
func (e Engine) audit(
	ctx context.Context,
	run engines.Run,
	account, inputs string,
	encoder *json.Encoder,
	sink scan.Sink,
	progress *progress,
) error {
	report := filepath.Join(run.WorkDir, ReportFile(account))
	invocation := &engines.Invocation{
		Bin:     run.Bin,
		Args:    args(run.Config, account, inputs, report),
		WorkDir: run.WorkDir,
		Stdout:  logWriter{sink: sink},
		Stderr:  logWriter{sink: sink},
		Env:     credentials(account),
	}

	sink.Log(fmt.Sprintf("auditing %s", account))
	result := invocation.Run(ctx)

	// The report is read before the exit code is judged: a run cancelled or
	// killed part way still leaves whatever it had written, and discarding that
	// would throw away findings that were genuinely observed.
	parsed, readErr := readExecJSON(report)
	if parsed != nil {
		emitted := parsed.Findings(account)
		for _, found := range emitted {
			if err := encoder.Encode(found); err != nil {
				return fmt.Errorf("write finding: %w", err)
			}
			if err := sink.Finding(found); err != nil {
				return err
			}
		}
		progress.account(parsed.Count(), len(emitted))
	}

	if !ranToCompletion(result.ExitCode) {
		if result.Err != nil {
			return fmt.Errorf("inspec against %s: %w", account, result.Err)
		}
		return fmt.Errorf("inspec against %s exited %d", account, result.ExitCode)
	}
	if readErr != nil {
		return readErr
	}
	return nil
}

// ranToCompletion reports whether an exit code means InSpec finished.
func ranToCompletion(code int) bool {
	return code == exitAllPassed || code == exitFailed || code == exitSkipped
}

// args builds one invocation's command line.
func args(config map[string]any, account, inputs, report string) []string {
	profile, _ := config["profile"].(string)

	built := []string{
		"exec", profile,
		"--target", targetURI(account),
		"--input-file", inputs,
		"--reporter", "json:" + report,
		"--no-color",
		// Without this InSpec checks for a newer release on every run, which
		// puts a network call between the operator and their results.
		"--chef-license", "accept-silent",
	}

	if controls := stringList(config["controls"]); len(controls) > 0 {
		built = append(built, "--controls")
		built = append(built, controls...)
	}
	return built
}

// targetURI is the train URI InSpec connects through. The project is passed as
// an input rather than in the URI, which is how the GCP benchmark reads it.
func targetURI(string) string { return "gcp://" }

// credentials are the environment variables the GCP transport authenticates
// with.
//
// Only the project is set here. The credentials themselves come from
// Application Default Credentials, which the provider's own SDK finds — copying
// them into the environment would mean recon handling secrets it has no reason
// to touch.
func credentials(account string) map[string]string {
	return map[string]string{
		"GOOGLE_CLOUD_PROJECT":  account,
		"CLOUDSDK_CORE_PROJECT": account,
	}
}

// Command renders the equivalent command line, for the record kept on the scan.
//
// It describes the first account only. A run over several accounts is several
// invocations differing in one input, and listing all of them would bury what
// someone actually wants to copy.
func (Engine) Command(run engines.Run) []string {
	account := "<project>"
	if accounts, err := readAccounts(run.In); err == nil && len(accounts) > 0 {
		account = accounts[0]
	}
	inputs := filepath.Join(run.WorkDir, InputsFile)
	report := filepath.Join(run.WorkDir, ReportFile(account))

	bin := run.Bin
	if bin == "" {
		bin = "cinc-auditor"
	}
	return append([]string{bin}, args(run.Config, account, inputs, report)...)
}

// readAccounts reads the rendered input list the runtime wrote.
func readAccounts(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read account list: %w", err)
	}

	var accounts []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// The list holds transport URIs so it reads as something a person could
		// paste; the benchmark wants the bare project id.
		if _, id, found := strings.Cut(line, "://"); found {
			line = id
		}
		accounts = append(accounts, line)
	}

	if len(accounts) == 0 {
		return nil, fmt.Errorf("account list %s is empty: there is nothing to audit", path)
	}
	return accounts, nil
}

// writeInputs renders the profile's inputs and returns the file's path.
//
// A file rather than repeated --input flags: an input can be a list, and a flag
// value is a string, so `gce_zones` would arrive as one comma-joined zone name
// that matches nothing.
func writeInputs(run engines.Run) (string, error) {
	inputs := map[string]any{}
	for key, name := range inputKeys {
		value, present := run.Config[key]
		if !present || value == nil {
			continue
		}
		if list, ok := asList(value); ok {
			if len(list) == 0 {
				continue
			}
			inputs[name] = list
			continue
		}
		inputs[name] = value
	}

	body, err := yaml.Marshal(inputs)
	if err != nil {
		return "", fmt.Errorf("render inputs: %w", err)
	}

	path := filepath.Join(run.WorkDir, InputsFile)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", fmt.Errorf("write inputs: %w", err)
	}
	return path, nil
}

// readExecJSON parses one account's exec-json.
func readExecJSON(path string) (*ExecJSON, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inspec report: %w", err)
	}

	var report ExecJSON
	if err := json.Unmarshal(body, &report); err != nil {
		return nil, fmt.Errorf("parse inspec report %s: %w", filepath.Base(path), err)
	}
	return &report, nil
}

// timeLimit reads the run's own deadline.
func timeLimit(config map[string]any) time.Duration {
	seconds, ok := asNumber(config["max-time"])
	if !ok || seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// logWriter forwards process output to the sink as it arrives, so a benchmark
// that takes minutes shows progress rather than nothing.
type logWriter struct{ sink scan.Sink }

func (w logWriter) Write(p []byte) (int, error) {
	if text := strings.TrimRight(string(p), "\n"); text != "" {
		w.sink.Log(text)
	}
	return len(p), nil
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
