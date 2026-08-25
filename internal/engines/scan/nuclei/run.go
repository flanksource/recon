package nuclei

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/engines"
	"github.com/flanksource/recon/internal/engines/scan"
)

// Run executes one scan in this process.
//
// Nuclei is linked in rather than spawned, so there is no output to parse and no
// exit code to interpret: findings arrive as values, progress as counters, and
// cancellation is the context. What the runtime still gets on disk is the JSONL
// result file, written here — it is the run's evidence, and it outlives the
// process that produced it.
func (Engine) Run(ctx context.Context, run engines.Run, sink scan.Sink) error {
	opts, err := Options(run.Config)
	if err != nil {
		return err
	}

	// -max-time is a process soft-kill on the command line. There is no process
	// to kill here, so it becomes the deadline it always meant.
	if limit, ok := run.Config["max-time"].(string); ok && limit != "" {
		budget, err := time.ParseDuration(limit)
		if err != nil {
			return fmt.Errorf("nuclei option \"max-time\": not a duration: %w", err)
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, budget)
		defer cancel()
	}

	targets, err := os.Open(run.In)
	if err != nil {
		return fmt.Errorf("read scan input: %w", err)
	}
	defer func() { _ = targets.Close() }()

	results, err := os.Create(run.Out)
	if err != nil {
		return fmt.Errorf("create findings file: %w", err)
	}
	defer func() { _ = results.Close() }()

	// Traffic is counted for every scan rather than behind nuclei's -http-stats
	// flag. That flag is read by nuclei's own command-line runner, which recon
	// does not go through, so honouring it would mean carrying an option that
	// only ever switched on a panel the scan page shows unconditionally.
	traffic := newHTTPStats()

	engine, err := nuclei.NewNucleiEngineCtx(ctx,
		nuclei.WithOptions(opts),
		nuclei.UseStatsWriter(newProgress(sink, traffic)),
		nuclei.UseOutputWriter(traffic),
		nuclei.WithLogger(sinkLogger(sink)),
		// A scan must never rewrite the templates underneath itself: the preview
		// the user approved was computed against what is on disk now.
		nuclei.WithTemplateUpdateCallback(true, nil),
	)
	if err != nil {
		return fmt.Errorf("configure nuclei: %w", err)
	}
	defer engine.Close()

	// Never probed. Probing exists to find a scheme for a bare host, and it does
	// so by prepending one unconditionally — nuclei's ProbeURL does not notice an
	// input that already has one. Recon resolves every endpoint to a full URL
	// before it gets here, so probing would turn http://host:5000 into
	// http://http://host:5000 and every finding would name a host that does not
	// exist.
	engine.LoadTargetsFromReader(targets, false)

	// Every endpoint the run was pointed at, recorded whether or not a template
	// fires against it. Read from the same file nuclei was handed rather than
	// synthesised from the findings, because findings only exist where
	// something was wrong: an endpoint nothing matched would otherwise be
	// indistinguishable from one that was never scanned.
	//
	// No verdicts. A template that matched nothing did not pass — that is
	// already this codebase's position in api.ScanStats.PassRecorded — so
	// nothing here ever resolves an earlier finding, and an open finding on a
	// nuclei endpoint stays open with an ageing last_seen, which is the truth.
	if err := emitEndpoints(run.In, sink); err != nil {
		return err
	}

	collected := newCollector(sink, results)
	err = engine.ExecuteCallbackWithCtx(ctx, collected.Event)

	// Reported even when the scan failed: what it skipped is usually why.
	if reportErr := collected.Report(); err == nil && reportErr != nil {
		return fmt.Errorf("record findings: %w", reportErr)
	}
	if err != nil {
		return fmt.Errorf("nuclei scan: %w", err)
	}
	return nil
}

// convert turns one nuclei result into the record written to disk and the
// normalised finding the UI renders.
//
// Both come from the same event so they cannot disagree. The record keeps
// nuclei's own JSON shape — the result file is read by things that are not
// recon — minus the base64 copy of the whole template nuclei attaches to every
// finding, which is large and which nothing reads.
func convert(event *output.ResultEvent) (map[string]any, api.Finding, error) {
	raw := map[string]any{}
	if encoded, err := json.Marshal(event); err == nil {
		_ = json.Unmarshal(encoded, &raw)
		delete(raw, "template-encoded")
	}

	name := event.Info.Name
	if name == "" {
		name = event.TemplateID
	}

	var reference []string
	if event.Info.Reference != nil {
		reference = event.Info.Reference.ToSlice()
	}

	host := hostOf(event)
	resource, err := resultResource(event)
	if err != nil {
		return nil, api.Finding{}, err
	}

	return raw, api.Finding{
		TemplateID:  event.TemplateID,
		Name:        name,
		Severity:    api.ParseSeverity(event.Info.SeverityHolder.Severity.String()),
		Host:        host,
		MatchedAt:   firstNonEmpty(event.Matched, event.URL, host),
		MatcherName: event.MatcherName,
		Type:        event.Type,
		Tags:        orEmpty(event.Info.Tags.ToSlice()),
		Timestamp:   event.Timestamp.Format(time.RFC3339),
		Extracted:   event.ExtractedResults,
		Remediation: event.Info.Remediation,
		Reference:   reference,
		Curl:        event.CURLCommand,
		Request:     event.Request,
		Response:    event.Response,
		Resources:   []api.ResourceRef{resource.Ref()},
		Raw:         raw,
	}, nil
}

func resultResource(event *output.ResultEvent) (api.Resource, error) {
	identity := event.URL
	if identity == "" && event.Type != "http" && event.Type != "https" {
		identity = event.Host
	}
	if identity == "" {
		return api.Resource{}, fmt.Errorf("nuclei result %s has no canonical input URL", event.TemplateID)
	}
	return endpointResource(identity), nil
}

// sinkLogger routes nuclei's own logging into the run's output stream, which is
// what the live console renders. Without it a linked-in scan would be silent
// where the subprocess was chatty, and "nothing is happening" and "it is
// working" would look identical.
func sinkLogger(sink scan.Sink) *gologger.Logger {
	logger := gologger.DefaultLogger
	instance := &gologger.Logger{}
	*instance = *logger
	instance.SetMaxLevel(levels.LevelInfo)
	instance.SetWriter(&sinkWriter{sink: sink})
	return instance
}

type sinkWriter struct {
	sink scan.Sink
}

func (w *sinkWriter) Write(data []byte, level levels.Level) {
	if len(data) == 0 {
		return
	}
	w.sink.Log(string(data) + "\n")
}

var _ writer.Writer = (*sinkWriter)(nil)

// hostOf names the host a result concerns. Nuclei leaves Host unset on some
// protocols, where the only address is the URL the template matched at.
func hostOf(event *output.ResultEvent) string {
	if event.Host != "" {
		return event.Host
	}
	return engines.HostOf(firstNonEmpty(event.Matched, event.URL))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func orEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
