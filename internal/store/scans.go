package store

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/flanksource/commons/logger"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// ScanOpts selects scan runs.
type ScanOpts struct {
	Engine   []string `flag:"engine" help:"Only runs of these engines"`
	Profile  []string `flag:"profile" help:"Only runs of these profiles"`
	Phase    []string `flag:"phase" help:"Only runs in these phases (idle, queued, running, done, failed, cancelled)"`
	Severity []string `flag:"severity" help:"Only runs that found at least one finding of these severities"`
	Since    string   `flag:"since" help:"Only runs started since this time (RFC3339 or a duration such as 24h)"`
	Limit    int      `flag:"limit" help:"Most recent N runs" default:"100"`
}

// Scope pushes the selector into SQL.
func (o ScanOpts) Scope(db *gorm.DB) (*gorm.DB, error) {
	if len(o.Engine) > 0 {
		db = db.Where("engine = ANY(?)", stringArray(o.Engine))
	}
	if len(o.Profile) > 0 {
		db = db.Where("profile = ANY(?)", stringArray(o.Profile))
	}
	if len(o.Phase) > 0 {
		db = db.Where("phase = ANY(?)", stringArray(o.Phase))
	}
	// A run "has" a severity when its denormalised counts record more than zero
	// of it, which is why those counts are on the row at all.
	for _, severity := range o.Severity {
		db = db.Where("COALESCE((severities ->> ?)::int, 0) > 0", severity)
	}
	if o.Since != "" {
		since, err := parseSince(o.Since)
		if err != nil {
			return nil, err
		}
		db = db.Where("started_at >= ?", since)
	}
	return db, nil
}

// ListScans returns the runs a selector matches, newest first.
func (s *Store) ListScans(ctx context.Context, opts ScanOpts) ([]api.Scan, error) {
	query, err := opts.Scope(s.DB(ctx))
	if err != nil {
		return nil, err
	}
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	}

	var rows []models.Scan
	if err := query.Order("started_at DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}

	return s.scanDocuments(ctx, rows)
}

// GetScan returns one run.
func (s *Store) GetScan(ctx context.Context, id string) (api.Scan, error) {
	row, err := s.scanRow(ctx, id)
	if err != nil {
		return api.Scan{}, err
	}
	counts, err := s.findingCount(ctx, row.ID)
	if err != nil {
		return api.Scan{}, err
	}
	hosts, err := s.scanHosts(ctx, row)
	if err != nil {
		return api.Scan{}, err
	}
	label, err := selectorLabel(row)
	if err != nil {
		return api.Scan{}, err
	}
	document := row.Document(counts, hosts, label)
	var output models.ScanOutput
	if err := s.DB(ctx).Where("scan_id = ?", row.ID).Take(&output).Error; err != nil {
		if IsNotFound(err) {
			return document, nil
		}
		return api.Scan{}, fmt.Errorf("get output for scan %s: %w", row.ID, err)
	}
	document.OutputCaptured = true
	document.Stdout = output.Stdout
	document.Stderr = output.Stderr
	document.StdoutTruncated = output.StdoutTruncated
	document.StderrTruncated = output.StderrTruncated
	return document, nil
}

// scanRow resolves a run by id or by name, because a name is what the results
// file is called and what anyone reading the runs list will type.
func (s *Store) scanRow(ctx context.Context, id string) (models.Scan, error) {
	var row models.Scan
	err := s.DB(ctx).Where("id::text = ? OR name = ?", id, id).First(&row).Error
	if err != nil {
		if IsNotFound(err) {
			return models.Scan{}, NotFound("scan", id)
		}
		return models.Scan{}, fmt.Errorf("get scan %s: %w", id, err)
	}
	return row, nil
}

func (s *Store) findingCount(ctx context.Context, scanID string) (int, error) {
	var count int64
	err := s.DB(ctx).Model(&models.Finding{}).Where("scan_id = ?", scanID).Count(&count).Error
	if err != nil {
		return 0, fmt.Errorf("count findings for %s: %w", scanID, err)
	}
	return int(count), nil
}

// scanHosts lists the hosts a run has something to say about.
//
// For an engine that reports findings that is the hosts it found something on,
// which is what the runs list means by "affected". A liveness sweep finds
// nothing by design, so its hosts are the ones it probed — read from the sweep's
// own results, which share the run's id.
func (s *Store) scanHosts(ctx context.Context, row models.Scan) ([]string, error) {
	var hosts []string
	query := s.DB(ctx).Model(&models.Finding{}).Where("scan_id = ?", row.ID)
	if row.Engine == api.ProbeEngine {
		query = s.DB(ctx).Model(&models.ProbeResult{}).Where("probe_id = ?", row.ID)
	}
	if err := query.Distinct().Order("host").Pluck("host", &hosts).Error; err != nil {
		return nil, fmt.Errorf("hosts for scan %s: %w", row.ID, err)
	}
	return hosts, nil
}

// selectorLabel renders the stored selector back into the phrase the UI shows.
// It is derived rather than stored so that a change to how selectors read does
// not need a migration.
func selectorLabel(row models.Scan) (string, error) {
	opts, err := TargetOptsFrom(row.Selector.Get())
	if err != nil {
		return "", fmt.Errorf("scan %s selector: %w", row.ID, err)
	}
	return opts.Describe(), nil
}

// CreateScan records a run before it starts, so a crashed process still leaves
// evidence that something was attempted.
func (s *Store) CreateScan(ctx context.Context, scan models.Scan) (models.Scan, error) {
	if scan.StartedAt.IsZero() {
		scan.StartedAt = time.Now()
	}
	if scan.Phase == "" {
		scan.Phase = string(api.PhaseIdle)
	}
	// The column is NOT NULL with a default, but gorm sends an explicit NULL
	// for a nil wrapper rather than omitting the column, so the default never
	// applies. A run that has found nothing yet has zero of every severity.
	if scan.Severities.V == nil {
		counts := api.SeverityCounts(nil)
		scan.Severities = models.Wrap(&counts)
	}
	if err := s.DB(ctx).Create(&scan).Error; err != nil {
		return models.Scan{}, fmt.Errorf("create scan: %w", err)
	}
	return scan, nil
}

// UpdateScan writes the run's terminal state.
func (s *Store) UpdateScan(ctx context.Context, scan models.Scan) error {
	return updateScan(s.DB(ctx), scan)
}

func updateScan(db *gorm.DB, scan models.Scan) error {
	result := db.Model(&models.Scan{}).Where("id = ?", scan.ID).Updates(map[string]any{
		"phase":          scan.Phase,
		"started_at":     scan.StartedAt,
		"finished_at":    scan.FinishedAt,
		"duration_ms":    scan.DurationMS,
		"exit_code":      scan.ExitCode,
		"error":          scan.Error,
		"command":        scan.Command,
		"stats":          scan.Stats,
		"severities":     scan.Severities,
		"muted":          scan.Muted,
		"result_path":    scan.ResultPath,
		"engine_version": scan.EngineVersion,
		"endpoint_count": scan.EndpointCount,
	})
	if result.Error != nil {
		return fmt.Errorf("update scan %s: %w", scan.ID, result.Error)
	}
	if result.RowsAffected != 1 {
		return NotFound("scan", scan.ID)
	}
	return nil
}

// FinalizeScan stores terminal metadata, findings, and bounded process output as
// one record. Readers never observe a terminal scan whose evidence is missing.
type FinalizeScanOptions struct {
	Scan     models.Scan
	Output   models.ScanOutput
	Findings []api.Finding

	// TargetIDs is what the run covered — the stable inventory identities it
	// resolved at the start, not only targets that produced findings. Each one's
	// scan.last_scan is stamped, which is the only thing that writes that field.
	TargetIDs []string

	// CountFindings stamps each host's scan.last_findings from this run. False
	// for a run that cannot produce any: a liveness sweep leaves the count from
	// the last real scan alone rather than zeroing it.
	CountFindings bool

	// Resources are the subjects the run examined, whatever the verdict —
	// including the ones every check passed on, which is what makes a clean
	// resource distinguishable from one nobody looked at. Each carries the
	// checks that reported a verdict against it, and those verdicts are what
	// let this run resolve an earlier run's findings.
	Resources []api.Resource

	// Muted are the findings a rule removed and MutedBy is mute.Result.ByRule.
	// The rows are not written, so this is the only way a muted check stops
	// looking like silence.
	Muted   []api.Finding
	MutedBy map[string][]int
}

func (s *Store) FinalizeScan(ctx context.Context, options FinalizeScanOptions) error {
	phase := api.Phase(options.Scan.Phase)
	if !phase.Terminal() {
		return fmt.Errorf("finalize scan %s: phase %q is not terminal", options.Scan.ID, phase)
	}
	if options.Scan.FinishedAt == nil {
		return fmt.Errorf("finalize scan %s: finished time is required", options.Scan.ID)
	}
	if options.Scan.DurationMS < 0 {
		return fmt.Errorf("finalize scan %s: duration cannot be negative", options.Scan.ID)
	}

	seen := *options.Scan.FinishedAt

	// Absent stats are not a claim that nothing passed. A run that recorded no
	// statistics at all — a cancellation persisted before the engine started,
	// or an engine that reports none — must resolve nothing from silence, which
	// is what a false PassRecorded gives.
	passRecorded := options.Scan.Stats.V != nil && options.Scan.Stats.V.PassRecorded

	// The order inside the transaction is forced twice, and both orderings are
	// load-bearing: resources before findings, because a finding's resource_id
	// is a foreign key and the ids only exist once the upsert has returned
	// them; and findings before reconciliation, because the ledger attaches the
	// evidence row it just wrote.
	return s.DB(ctx).Transaction(func(tx *gorm.DB) error {
		// Finalizes of one engine run one at a time.
		//
		// resolveAbsentSQL closes whatever a run did not restate, and it decides
		// that by `last_scan_id <> this run`. Two runs of the same engine over an
		// overlapping account and check set — two profiles usually do overlap —
		// each read the other's freshly opened rows as carrying an older run and
		// resolve them. Neither transaction conflicts, so both commit and the
		// findings are simply gone.
		//
		// Per engine rather than per account: one lock cannot deadlock, and a
		// finalize is short next to the scan that produced it. The queue already
		// serialises within a process (internal/scan/supervise.go), so this is
		// what covers a second recon against the same database.
		if err := tx.Exec(
			"SELECT pg_advisory_xact_lock(hashtext(?)::bigint)", options.Scan.Engine).Error; err != nil {
			return fmt.Errorf("lock engine %s for finalize: %w", options.Scan.Engine, err)
		}
		ids, err := upsertResources(tx, options.Scan.ID, options.Scan.Engine, seen, options.Resources)
		if err != nil {
			return err
		}
		if err := saveFindings(tx, options.Scan.ID, options.Findings, ids); err != nil {
			return err
		}
		if err := updateScan(tx, options.Scan); err != nil {
			return err
		}
		if err := stampScanned(tx, options); err != nil {
			return err
		}
		if err := reconcileFindingStates(tx, reconcileOptions{
			ScanID:       options.Scan.ID,
			Engine:       options.Scan.Engine,
			At:           seen,
			Resources:    options.Resources,
			IDs:          ids,
			Terminal:     phase == api.PhaseDone,
			PassRecorded: passRecorded,
			Muted:        options.Muted,
			MutedBy:      options.MutedBy,
		}); err != nil {
			return err
		}

		// Skipped for a run with nothing to capture: an engine that runs in this
		// process leaves no streams, and an empty row would make the API report
		// captured output that does not exist.
		if options.Output == (models.ScanOutput{}) {
			return nil
		}
		options.Output.ScanID = options.Scan.ID
		if err := tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "scan_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"stdout", "stderr", "stdout_truncated", "stderr_truncated",
			}),
		}).Create(&options.Output).Error; err != nil {
			return fmt.Errorf("save output for scan %s: %w", options.Scan.ID, err)
		}
		return nil
	})
}

// stampScanned records on every target the run covered that it was covered, and
// by how much.
//
// One statement rather than a read-modify-write per host: a full-estate scan
// covers hundreds of targets, and the count comes from the findings this run
// just wrote inside the same transaction. A named host that is not in the
// inventory is simply not updated — the same rule the probe runner applies, and
// inventing a record is discovery's job.
// stampScannedSQL is at package scope so a test can render it without a
// database — see scans_sql_test.go, which is the only guard against the named
// parameters silently becoming literal text.
//
// CAST(@x AS type) rather than @x::type: gorm ends a named parameter at a space,
// comma, bracket or quote and not at a colon, so `@at::text` is read as a
// parameter literally called "at::text", matches nothing, and is emitted
// verbatim into the SQL.
const stampScannedSQL = `
UPDATE targets AS t
SET scan = COALESCE(t.scan, '{}'::jsonb)
        || jsonb_build_object('last_scan', CAST(@at AS text))
        || CASE WHEN CAST(@count AS boolean)
                THEN jsonb_build_object('last_findings', COALESCE(c.n, 0))
                ELSE '{}'::jsonb END,
    updated_at = now()
FROM unnest(CAST(@targets AS text[])) AS sel(id)
LEFT JOIN (
    SELECT target_id, COUNT(*) AS n FROM findings
    WHERE scan_id = @scan AND target_id IS NOT NULL AND target_id <> ''
    GROUP BY target_id
) AS c ON c.target_id = sel.id
WHERE t.id = sel.id`

func stampScanned(db *gorm.DB, options FinalizeScanOptions) error {
	if len(options.TargetIDs) == 0 {
		return nil
	}

	err := db.Exec(stampScannedSQL,
		map[string]any{
			// RFC3339 because that is what the target schema declares and what
			// ApplyProbe writes into the sibling observed timestamps.
			"at":      options.Scan.FinishedAt.Format(time.RFC3339),
			"count":   options.CountFindings,
			"targets": stringArray(options.TargetIDs),
			"scan":    options.Scan.ID,
		},
	).Error
	if err != nil {
		return fmt.Errorf("stamp scan %s onto its targets: %w", options.Scan.ID, err)
	}
	return nil
}

func saveFindings(db *gorm.DB, scanID string, findings []api.Finding, ids map[api.ResourceKey]string) error {
	if len(findings) == 0 {
		return nil
	}

	// A finding is linked to the first resource it names and no others. A
	// record may mention several, and they all become rows, but the verdict is
	// about one subject: counting it against everything the check merely
	// mentioned would let one PASS resolve findings on resources the check
	// never judged.
	rows := make([]models.Finding, 0, len(findings))
	// linked[i] are the resources rows[i] names, by their position in the
	// engine's own record, so a subject recon could not resolve leaves a gap
	// rather than renumbering the ones around it.
	linked := make([][]models.FindingResource, 0, len(findings))
	var unattached []string
	for _, finding := range findings {
		// Loudly, because the alternative is silent: unnumbered findings would
		// all claim line 0 and collide on findings_scan_line_key, and whichever
		// one won would be the run's only recorded result.
		if finding.LineNo <= 0 {
			return fmt.Errorf(
				"save findings for %s: %q has no line number; a finding is addressed by the line it "+
					"occupied in the engine's own output, and the caller assigns it",
				scanID, finding.TemplateID)
		}
		if finding.TargetID == "" {
			finding.TargetID = finding.Host
		}
		// The caller's line number, not this loop's index. line_no is the line
		// of the engine's own findings file, and a run whose mute rules removed
		// some findings keeps the survivors on the lines they came from — so
		// the artifact and the database still address the same evidence, with
		// gaps where a rule dropped something. Renumbering here would silently
		// break that correspondence for exactly the runs that need it.
		// A finding whose subject this run did not also emit as a resource is
		// recorded without one rather than discarded, and it does not take the
		// run down with it.
		//
		// resource_id is nullable and openFromFindingsSQL skips a NULL, so such a
		// finding is evidence with no lifecycle — which is a real, if lesser,
		// thing to be. Erroring here cost the whole FinalizeScan transaction: the
		// run's terminal phase, its process output, its resources and every other
		// finding it wrote. That is reachable from one malformed record, and
		// routinely for nuclei, whose resources come from the input file
		// (endpoints.go) while a finding's come from event.URL falling back to
		// event.Host — so a dns or ssl template against an `https://…/` input
		// line yields a uid the run never emitted.
		//
		// Loud rather than silent: the count is `resource_id IS NULL` for the
		// scan, which is queryable and cannot drift the way a counter column
		// would.
		resourceID := ""
		switch {
		case len(finding.Resources) == 0:
			unattached = append(unattached, finding.TemplateID)
		default:
			resolved, err := resolveResource(ids, finding.Resources[0])
			if err != nil {
				unattached = append(unattached, finding.TemplateID)
			}
			resourceID = resolved
		}
		rows = append(rows, models.FindingFrom(scanID, finding.LineNo, finding, resourceID))
		// Every subject, not only the canonical one. The rest have nowhere else
		// to live: they are recoverable from the engine's own record and from
		// nothing recon stores, and that record is going away.
		linked = append(linked, resolvedResources(ids, finding.Resources))
	}
	if len(unattached) > 0 {
		slices.Sort(unattached)
		logger.Warnf("scan %s: %d of %d findings name a resource the run did not emit, "+
			"so they carry no lifecycle: %s", scanID, len(unattached), len(findings),
			strings.Join(slices.Compact(unattached), ", "))
	}
	// Batched: a broad scan can produce tens of thousands of findings, and one
	// statement per row would dominate the run's wall clock.
	if err := db.CreateInBatches(rows, 500).Error; err != nil {
		return fmt.Errorf("save findings for %s: %w", scanID, err)
	}

	var links []models.FindingResource
	for index, row := range rows {
		if row.ID == "" {
			return fmt.Errorf(
				"save findings for %s: the insert returned no id for %q, so the resources it "+
					"names cannot be linked", scanID, row.TemplateID)
		}
		for _, link := range linked[index] {
			link.FindingID = row.ID
			links = append(links, link)
		}
	}
	return saveFindingResources(db, links)
}

// resolvedResources names the rows a finding's references resolve to, in the
// order the engine's own record named them.
//
// A reference that resolves to nothing is skipped rather than failing the
// finding: the same record can name a subject the run emitted and one it did
// not, and the second is no reason to lose the first. Ordinals are the position
// in the original record, so a skipped subject leaves a gap instead of
// renumbering the ones after it.
//
// A resource named twice is kept once, at its first position. The relation is
// keyed by the pair, and a record that repeats a subject is still describing one
// subject.
func resolvedResources(ids map[api.ResourceKey]string, refs []api.ResourceRef) []models.FindingResource {
	if len(refs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(refs))
	found := make([]models.FindingResource, 0, len(refs))
	for ordinal, ref := range refs {
		resolved, err := resolveResource(ids, ref)
		if err != nil {
			continue
		}
		if _, repeated := seen[resolved]; repeated {
			continue
		}
		seen[resolved] = struct{}{}
		found = append(found, models.FindingResource{ResourceID: resolved, Ordinal: ordinal})
	}
	return found
}
