package httpapi

import (
	"context"
	"fmt"
	"net/http"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/scan"
)

// ScanReader resolves a run. It is the store's GetScan, narrowed to what these
// routes need.
type ScanReader interface {
	GetScan(ctx context.Context, id string) (api.Scan, error)
}

// RegisterScanFiles serves a run's retained artifacts.
//
// These are not entity operations: the subject is a directory on disk that the
// run points at, and the payload of the second route is a file rather than
// JSON. Serving them is what makes the retained directory reachable from the
// scan page — the recorded path alone only helps someone sitting at the machine
// that ran the scan.
func RegisterScanFiles(mux *http.ServeMux, scans ScanReader) {
	mux.HandleFunc("GET /api/scan/{id}/files", func(w http.ResponseWriter, r *http.Request) {
		dir, run, err := artifactDir(r, scans)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		files, err := scan.ListArtifacts(dir)
		if err != nil {
			// The run names a directory that is no longer readable — pruned,
			// moved, or on a disk this process cannot see. Reported as gone
			// rather than as an empty listing, which would read as "the scan
			// produced nothing".
			writeError(w, http.StatusGone, err)
			return
		}
		writeJSON(w, api.ScanFiles{ScanID: run.ID, Path: dir, Files: files})
	})

	mux.HandleFunc("GET /api/scan/{id}/files/{name}", func(w http.ResponseWriter, r *http.Request) {
		dir, _, err := artifactDir(r, scans)
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		path, err := scan.ResolveArtifact(dir, r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		// Always as text: these are JSONL, plain lists and logs, and a browser
		// that decides to download findings.jsonl instead of showing it is the
		// slower way to answer "what did this run see".
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.ServeFile(w, r, path)
	})
}

func artifactDir(r *http.Request, scans ScanReader) (string, api.Scan, error) {
	run, err := scans.GetScan(r.Context(), r.PathValue("id"))
	if err != nil {
		return "", api.Scan{}, err
	}
	if run.Result == "" {
		return "", run, fmt.Errorf("scan %s kept no artifacts: it ran before results were retained", run.Name)
	}
	return run.Result, run, nil
}
