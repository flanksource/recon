package missioncontrol

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	dutymodels "github.com/flanksource/duty/models"
	"github.com/flanksource/duty/upstream"
	"github.com/flanksource/incident-commander/sdk"

	"github.com/flanksource/recon/internal/api"
)

// DefaultAgent is the name recon pushes under. Mission Control creates the
// agent on first push, so this only has to be stable — every upload from every
// recon install lands under the same name unless one is chosen.
const DefaultAgent = "recon"

// UnresolvedPolicy says what an upload does about findings nothing in the
// catalog claims.
type UnresolvedPolicy string

const (
	// UnresolvedReport uploads what resolved and lists the rest.
	UnresolvedReport UnresolvedPolicy = "report"
	// UnresolvedError pushes nothing unless every finding resolved, for a
	// caller that needs the upload to be all or nothing.
	UnresolvedError UnresolvedPolicy = "error"
)

// UploadOptions are the choices an upload takes.
type UploadOptions struct {
	// Context names a faro context; empty uses the current one.
	Context string
	Agent   string
	// MinSeverity drops anything less severe. Empty keeps everything.
	MinSeverity api.Severity
	DryRun      bool
	Unresolved  UnresolvedPolicy
}

// Uploader turns a scan's findings into Mission Control insights.
type Uploader struct {
	Client   *sdk.Client
	Resolver *Resolver
	// Server and Context describe where the client points, for the report.
	Server  string
	Context string
}

// Upload resolves every finding against the catalog, maps it to an insight and
// pushes the batch.
//
// Resolution happens before anything is sent, so a dry run does the same work
// and reports the same coverage as a real upload — which is the point: the
// number worth knowing before writing to a shared system is how much of the run
// will land on the right resource.
func (u *Uploader) Upload(ctx context.Context, scan api.Scan, findings []api.Finding, targets map[string]api.TargetDocument, options UploadOptions) (api.Upload, error) {
	agent := options.Agent
	if agent == "" {
		agent = DefaultAgent
	}

	result := api.Upload{
		ScanID:  scan.ID,
		Engine:  scan.Engine,
		Context: u.Context,
		Server:  u.Server,
		Agent:   agent,
		DryRun:  options.DryRun,
		Total:   len(findings),
	}

	selected := atOrAbove(findings, options.MinSeverity)
	result.Findings = len(selected)

	analyses := make([]dutymodels.ConfigAnalysis, 0, len(selected))
	configs := map[string]*api.UploadConfig{}
	notes := map[string]bool{}

	for _, finding := range selected {
		match, unresolved, err := u.Resolver.Resolve(ctx, scan, finding, targets[finding.TargetID])
		if err != nil {
			return result, err
		}
		if unresolved != nil {
			result.Unresolved = append(result.Unresolved, *unresolved)
			continue
		}

		analysis, err := Analysis(scan, finding, match.ConfigID)
		if err != nil {
			return result, err
		}
		analyses = append(analyses, analysis)

		if match.RolledUp {
			result.RolledUp++
		} else {
			result.Resolved++
		}
		if match.Note != "" {
			notes[match.Note] = true
		}

		id := match.ConfigID.String()
		if configs[id] == nil {
			configs[id] = &api.UploadConfig{
				ID: id, Name: match.ConfigName, Type: match.ConfigType, RolledUp: match.RolledUp,
			}
		}
		configs[id].Insights++
	}

	result.Configs = sortedConfigs(configs)
	result.Notes = sortedKeys(notes)

	if options.Unresolved == UnresolvedError && len(result.Unresolved) > 0 {
		return result, fmt.Errorf("%d of %d findings could not be resolved to a Mission Control config item and --unresolved=error was set; nothing was pushed",
			len(result.Unresolved), len(selected))
	}

	if options.DryRun || len(analyses) == 0 {
		return result, nil
	}

	if err := u.Client.PushUpstream(ctx, agent, &upstream.PushData{ConfigAnalysis: analyses}); err != nil {
		return result, fmt.Errorf("push %d insights to %s: %w", len(analyses), u.Server, err)
	}
	result.Pushed = len(analyses)
	return result, nil
}

// atOrAbove keeps the findings at least as severe as the floor.
//
// `unknown` sits with `info` rather than below it: it is not a statement that
// something is unimportant, only that the engine used a vocabulary recon does
// not recognise, and ranking it last would quietly hide those findings from
// every filtered upload.
func atOrAbove(findings []api.Finding, floor api.Severity) []api.Finding {
	if floor == "" {
		return findings
	}
	limit := rank(floor)
	kept := make([]api.Finding, 0, len(findings))
	for _, finding := range findings {
		if rank(finding.Severity) <= limit {
			kept = append(kept, finding)
		}
	}
	return kept
}

func rank(severity api.Severity) int {
	if severity == api.SeverityUnknown {
		severity = api.SeverityInfo
	}
	return slices.Index(api.Severities(), severity)
}

func sortedConfigs(configs map[string]*api.UploadConfig) []api.UploadConfig {
	out := make([]api.UploadConfig, 0, len(configs))
	for _, config := range configs {
		out = append(out, *config)
	}
	// Most insights first, then by name, so the report leads with the resource
	// the run had most to say about and stays stable between runs.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Insights != out[j].Insights {
			return out[i].Insights > out[j].Insights
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// ParseUnresolvedPolicy validates the flag rather than falling back to a
// default: a caller who asked for `--unresolved=fail` meant something, and
// silently reporting instead would let a broken upload look clean.
func ParseUnresolvedPolicy(value string) (UnresolvedPolicy, error) {
	switch UnresolvedPolicy(strings.ToLower(strings.TrimSpace(value))) {
	case "", UnresolvedReport:
		return UnresolvedReport, nil
	case UnresolvedError:
		return UnresolvedError, nil
	default:
		return "", fmt.Errorf("unknown --unresolved policy %q: expected %q or %q", value, UnresolvedReport, UnresolvedError)
	}
}
