package store

import (
	"context"
	"fmt"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

// Projecting many scan rows at once.
//
// A scan's document carries two things the row does not: how many findings the
// run wrote and which hosts it has something to say about. Both were read one
// scan at a time, which is two extra round-trips per row on a listing that
// defaults to a hundred, and four per state on the insight sync — which runs
// unbounded and whose per-scan read also pulled scan_outputs.stdout and stderr,
// the megabytes that table was split off to keep out of exactly this path.
//
// Neither caller wants the output, so neither reads it.

// scanDocuments renders rows in the order given, with counts and hosts gathered
// in one query each.
func (s *Store) scanDocuments(ctx context.Context, rows []models.Scan) ([]api.Scan, error) {
	if len(rows) == 0 {
		return []api.Scan{}, nil
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}

	counts, err := s.findingCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	hosts, err := s.scanHostsByID(ctx, rows, ids)
	if err != nil {
		return nil, err
	}

	scans := make([]api.Scan, 0, len(rows))
	for _, row := range rows {
		label, err := selectorLabel(row)
		if err != nil {
			return nil, err
		}
		scans = append(scans, row.Document(counts[row.ID], hosts[row.ID], label))
	}
	return scans, nil
}

func (s *Store) findingCounts(ctx context.Context, ids []string) (map[string]int, error) {
	var rows []struct {
		ScanID string `gorm:"column:scan_id"`
		N      int    `gorm:"column:n"`
	}
	if err := s.DB(ctx).Model(&models.Finding{}).
		Select("scan_id, count(*) AS n").
		Where("scan_id = ANY(?)", stringArray(ids)).
		Group("scan_id").Scan(&rows).Error; err != nil {
		return nil, fmt.Errorf("count findings for %d scans: %w", len(ids), err)
	}
	counts := make(map[string]int, len(rows))
	for _, row := range rows {
		counts[row.ScanID] = row.N
	}
	return counts, nil
}

// scanHostsByID is the batched form of "the hosts a run has something to say
// about": the hosts it found something on, except for a liveness sweep, which
// finds nothing by design and so reports the ones it probed.
func (s *Store) scanHostsByID(
	ctx context.Context, rows []models.Scan, ids []string,
) (map[string][]string, error) {
	var probes []string
	for _, row := range rows {
		if row.Engine == api.ProbeEngine {
			probes = append(probes, row.ID)
		}
	}

	hosts := map[string][]string{}
	collect := func(query string, of []string) error {
		if len(of) == 0 {
			return nil
		}
		var found []struct {
			ScanID string `gorm:"column:scan_id"`
			Host   string `gorm:"column:host"`
		}
		if err := s.DB(ctx).Raw(query, stringArray(of)).Scan(&found).Error; err != nil {
			return fmt.Errorf("hosts for %d scans: %w", len(of), err)
		}
		for _, row := range found {
			hosts[row.ScanID] = append(hosts[row.ScanID], row.Host)
		}
		return nil
	}

	if err := collect(`SELECT scan_id, host FROM findings WHERE scan_id = ANY(?)
		GROUP BY scan_id, host ORDER BY scan_id, host`, ids); err != nil {
		return nil, err
	}
	if err := collect(`SELECT probe_id AS scan_id, host FROM probe_results WHERE probe_id = ANY(?)
		GROUP BY probe_id, host ORDER BY probe_id, host`, probes); err != nil {
		return nil, err
	}
	return hosts, nil
}

// scansByID reads the runs a page of states was last touched by.
func (s *Store) scansByID(ctx context.Context, states []api.FindingState) (map[string]api.Scan, error) {
	wanted := map[string]struct{}{}
	for _, state := range states {
		if state.LastScanID != "" {
			wanted[state.LastScanID] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return map[string]api.Scan{}, nil
	}

	var rows []models.Scan
	if err := s.DB(ctx).Where("id = ANY(?)", stringArray(keys(wanted))).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("read scans for %d finding states: %w", len(states), err)
	}
	documents, err := s.scanDocuments(ctx, rows)
	if err != nil {
		return nil, err
	}
	scans := make(map[string]api.Scan, len(documents))
	for _, scan := range documents {
		scans[scan.ID] = scan
	}
	return scans, nil
}
