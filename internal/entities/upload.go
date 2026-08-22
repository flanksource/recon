package entities

import (
	"context"
	"fmt"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/missioncontrol"
	"github.com/flanksource/recon/internal/store"
)

// uploadFlags are the choices a push into Mission Control takes.
//
// There is no server or token flag on purpose: the credential is faro's, so
// `faro auth login` is the setup and `--context` is the only thing left to
// choose between servers.
type uploadFlags struct {
	Context string `flag:"context" help:"Mission Control context to push to; defaults to the current faro context"`
	Agent   string `flag:"agent" help:"Agent name the insights are attributed to" default:"recon"`
	// Named severity rather than min-severity: every other filter in this CLI is
	// named for what it selects.
	Severity   string `flag:"severity" help:"Only upload findings at or above this severity"`
	Unresolved string `flag:"unresolved" help:"What to do with findings no config item claims: report or error" default:"report"`
	DryRun     bool   `flag:"dry-run" help:"Resolve and report what would be uploaded without writing anything"`
}

func (uploadFlags) ClickyActionFlags() {}

// uploadScan pushes one run's findings to Mission Control as insights.
func (r *Registry) uploadScan(ctx context.Context, id string, opts uploadFlags) (api.Upload, error) {
	st, err := r.store()
	if err != nil {
		return api.Upload{}, err
	}

	unresolved, err := missioncontrol.ParseUnresolvedPolicy(opts.Unresolved)
	if err != nil {
		return api.Upload{}, err
	}
	severity, err := parseMinSeverity(opts.Severity)
	if err != nil {
		return api.Upload{}, err
	}

	scan, err := st.GetScan(ctx, id)
	if err != nil {
		return api.Upload{}, err
	}
	// A run that never finished has not decided what it found, and uploading a
	// partial view of it would put insights upstream that the completed run
	// might not have produced.
	if !scan.Phase.Terminal() {
		return api.Upload{}, fmt.Errorf("scan %s is %s; only a finished run can be uploaded", scan.ID, scan.Phase)
	}

	findings, err := scanFindings(ctx, st, scan)
	if err != nil {
		return api.Upload{}, err
	}
	targets, err := findingTargets(ctx, st, findings)
	if err != nil {
		return api.Upload{}, err
	}

	uploader, err := missioncontrol.NewUploader(opts.Context)
	if err != nil {
		return api.Upload{}, err
	}
	return uploader.Upload(ctx, scan, findings, targets, missioncontrol.UploadOptions{
		Context:     opts.Context,
		Agent:       opts.Agent,
		MinSeverity: severity,
		DryRun:      opts.DryRun,
		Unresolved:  unresolved,
	})
}

// scanFindings reads every finding of a run.
//
// FindingOpts.Limit defaults to 500 for the list endpoint, which is a sensible
// page for a browser and completely wrong here: an upload that silently stopped
// at 500 would report a clean result while leaving the rest of the run behind.
// The run already recorded how many it has.
func scanFindings(ctx context.Context, st *store.Store, scan api.Scan) ([]api.Finding, error) {
	limit := scan.Findings
	if limit <= 0 {
		return nil, nil
	}
	findings, err := st.ListFindings(ctx, store.FindingOpts{Scan: []string{scan.ID}, Limit: limit})
	if err != nil {
		return nil, err
	}
	if len(findings) < scan.Findings {
		return nil, fmt.Errorf("scan %s records %d findings but only %d were read; refusing to upload a partial run",
			scan.ID, scan.Findings, len(findings))
	}
	return findings, nil
}

// findingTargets loads the inventory targets the findings point at, which is
// where the cluster and account a finding rolls up to comes from. A finding
// whose target has since been deleted simply has no scope to roll up to.
func findingTargets(ctx context.Context, st *store.Store, findings []api.Finding) (map[string]api.TargetDocument, error) {
	wanted := map[string]bool{}
	for _, finding := range findings {
		if finding.TargetID != "" {
			wanted[finding.TargetID] = true
		}
	}

	targets := make(map[string]api.TargetDocument, len(wanted))
	for id := range wanted {
		target, err := st.GetTarget(ctx, id)
		if err != nil {
			continue
		}
		targets[id] = target
	}
	return targets, nil
}

// parseMinSeverity refuses a severity it does not know rather than letting
// api.ParseSeverity fold it into `unknown`, which as a floor would silently
// keep everything.
func parseMinSeverity(value string) (api.Severity, error) {
	if value == "" {
		return "", nil
	}
	severity := api.ParseSeverity(value)
	if severity == api.SeverityUnknown && value != string(api.SeverityUnknown) {
		return "", fmt.Errorf("unknown severity %q: expected one of %v", value, api.Severities())
	}
	return severity, nil
}
