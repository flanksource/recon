package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/flanksource/recon/internal/api"
)

// Artifacts is a run's retained output directory.
//
// A scan used to run in a scratch directory that was deleted the moment it
// ended, so the engine's own JSONL — the artifact every other tool in this
// ecosystem reads — survived only as rows in Postgres. The directory is kept
// now, and the run records where it is.
//
// The layout is `results/<engine>/<date>/<run>/`. Partitioned by date because
// an estate scanned daily accumulates runs faster than one directory listing
// stays readable, and by engine because two engines' artifacts are not
// interchangeable even when they are both called findings.jsonl.
type Artifacts struct{ Dir string }

// Artifact file names. They are fixed rather than derived so that a directory
// from any run can be read without consulting the database first.
const (
	// TargetsFile is the resolved endpoint list the engine was given.
	TargetsFile = "targets.txt"

	// FindingsFile is the engine's own output, in its own format.
	FindingsFile = "findings.jsonl"

	// ConfigFile is the effective engine configuration: the stored profile with
	// the run's overrides already layered on, which is what actually ran and is
	// not recoverable from the profile afterwards.
	ConfigFile = "config.json"

	// MetadataFile is the run's terminal record — phase, timings, command,
	// counts, statistics. Written last, so its presence means the run finished.
	MetadataFile = "scan.json"

	// LogFile is the engine's log output, as far back as the buffer kept it.
	LogFile = "output.log"
)

// NewArtifacts creates the directory for one run.
func NewArtifacts(root, engine string, startedAt time.Time, name string) (Artifacts, error) {
	if root == "" {
		root = "."
	}
	dir := filepath.Join(root, "results", engine, startedAt.Format("2006-01-02"), name)
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return Artifacts{}, fmt.Errorf("resolve scan artifact dir: %w", err)
	}
	if err := os.MkdirAll(absolute, 0o755); err != nil {
		return Artifacts{}, fmt.Errorf("create scan artifact dir: %w", err)
	}
	return Artifacts{Dir: absolute}, nil
}

// Path names a file in the directory.
func (a Artifacts) Path(name string) string { return filepath.Join(a.Dir, name) }

// WriteJSON stores a document, indented: these are read by people as often as
// by programs.
func (a Artifacts) WriteJSON(name string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	return a.WriteFile(name, append(encoded, '\n'))
}

// WriteFile stores one artifact.
func (a Artifacts) WriteFile(name string, body []byte) error {
	if err := os.WriteFile(a.Path(name), body, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	return nil
}

// Remove deletes the directory. Used only when a run is abandoned before it
// produces anything — a run that started leaves its evidence behind.
func (a Artifacts) Remove() { _ = os.RemoveAll(a.Dir) }

// ListArtifacts reports what a run left in dir.
//
// Directories are skipped rather than descended: nothing writes one, and
// serving a listing that implies otherwise would promise downloads that fail.
func ListArtifacts(dir string) ([]api.ScanFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read scan artifacts: %w", err)
	}

	files := make([]api.ScanFile, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", entry.Name(), err)
		}
		files = append(files, api.ScanFile{
			Name:     entry.Name(),
			Size:     info.Size(),
			Modified: info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

// ResolveArtifact returns the path of one file in a run's directory.
//
// The name is matched against the listing rather than joined onto the
// directory. The directory comes from the database and the name from a URL, and
// a joined path is one `..` away from serving anything the process can read —
// checking that the name is something the run actually wrote removes the
// question entirely.
func ResolveArtifact(dir, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", fmt.Errorf("no such scan artifact: %s", name)
	}
	files, err := ListArtifacts(dir)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if file.Name == name {
			return filepath.Join(dir, name), nil
		}
	}
	return "", fmt.Errorf("no such scan artifact: %s", name)
}
