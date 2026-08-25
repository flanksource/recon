package nuclei

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/configdb"
	"github.com/flanksource/recon/internal/engines/scan"
)

// emitEndpoints records every endpoint the run was pointed at.
//
// Read from the input file rather than from what the scan found, because that
// is the only place the clean endpoints exist: a finding is written where
// something was wrong, so deriving the estate from findings would make "nothing
// matched here" and "this was never scanned" the same absence.
func emitEndpoints(path string, sink scan.Sink) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("read scan input: %w", err)
	}
	defer func() { _ = file.Close() }()

	seen := map[string]struct{}{}
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		target := strings.TrimSpace(lines.Text())
		if target == "" {
			continue
		}
		if _, already := seen[target]; already {
			continue
		}
		seen[target] = struct{}{}
		if err := sink.Resource(endpointResource(target)); err != nil {
			return err
		}
	}
	if err := lines.Err(); err != nil {
		return fmt.Errorf("read scan input: %w", err)
	}
	return nil
}

// endpointResource describes one scanned URL.
//
// Scope is the host and the uid is the whole URL, because the two are different
// questions: https://api.example.test/v1 and https://api.example.test/admin are
// separate subjects that a person groups by host. Recon resolves every endpoint
// to a full URL before nuclei sees it, so a bare host here is a malformed input
// rather than a case to normalise — it is kept as its own scope so it is still
// addressable rather than silently dropped.
func endpointResource(target string) api.Resource {
	scope := target
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		scope = parsed.Host
	}
	return api.Resource{
		Provider: "nuclei", Scope: scope, UID: target,
		Kind: api.KindEndpoint, Name: target, Type: "url",
		TargetID: scope,
		ExternalIDs: configdb.ExternalIDs(target, target),
	}
}
