// Package all registers every built-in engine.
//
// It exists so that importing one package wires up the whole catalog. Engines
// self-register from their init, so anything that needs the registries — the
// server, the CLI, the tests — imports this and nothing else.
package all

import (
	_ "github.com/flanksource/recon/internal/engines/discovery/dnsx"
	_ "github.com/flanksource/recon/internal/engines/discovery/httpx"
	_ "github.com/flanksource/recon/internal/engines/discovery/katana"
	_ "github.com/flanksource/recon/internal/engines/discovery/naabu"
	_ "github.com/flanksource/recon/internal/engines/discovery/subfinder"
	_ "github.com/flanksource/recon/internal/engines/discovery/tlsx"
	_ "github.com/flanksource/recon/internal/engines/scan/inspec"
	_ "github.com/flanksource/recon/internal/engines/scan/nuclei"
)
