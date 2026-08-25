// Command gen-ocsf generates the Go types recon stores a finding as, from the
// OCSF schema OCSF itself publishes.
//
// Generated from a vendored copy of https://schema.ocsf.io/<version>/export/schema
// rather than fetched at build time, so generation is hermetic and a version
// bump arrives as a reviewable diff of the schema rather than a silent change
// in generated output.
//
//	go run ./hack/gen-ocsf              # regenerate internal/ocsf
//	go run ./hack/gen-ocsf -check       # fail when the checked-in copy has drifted
//	go run ./hack/gen-ocsf -refresh 1.5.0
//
// -refresh reaches schema.ocsf.io and so has to run outside the development
// sandbox, whose network allowlist does not include it.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const exportURL = "https://schema.ocsf.io/%s/export/schema"

type options struct {
	RepositoryRoot string
	SchemaPath     string
	OutputDir      string
	Check          bool
	Refresh        string
}

func main() {
	var opts options
	flag.StringVar(&opts.RepositoryRoot, "repo", ".", "recon repository root")
	flag.StringVar(&opts.SchemaPath, "schema", "hack/gen-ocsf/schema/ocsf.json.xz", "vendored OCSF schema export")
	flag.StringVar(&opts.OutputDir, "out", "internal/ocsf", "generated package directory")
	flag.BoolVar(&opts.Check, "check", false, "fail when checked-in generated files have drifted")
	flag.StringVar(&opts.Refresh, "refresh", "", "fetch and re-vendor the OCSF schema export for this version")
	flag.Parse()

	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(opts options) error {
	schemaPath := filepath.Join(opts.RepositoryRoot, opts.SchemaPath)

	if opts.Refresh != "" {
		if opts.Check {
			return fmt.Errorf("-refresh rewrites the vendored schema and cannot be combined with -check")
		}
		if err := refreshSchema(opts.Refresh, schemaPath); err != nil {
			return err
		}
		fmt.Printf("vendored OCSF %s schema export to %s\n", opts.Refresh, opts.SchemaPath)
	}

	schema, err := loadExport(schemaPath)
	if err != nil {
		return err
	}
	built, err := build(schema)
	if err != nil {
		return err
	}
	files, err := render(built)
	if err != nil {
		return err
	}

	outputDir := filepath.Join(opts.RepositoryRoot, opts.OutputDir)
	if opts.Check {
		if err := checkGenerated(outputDir, files); err != nil {
			return err
		}
		fmt.Printf("OCSF generated types are current (OCSF %s, %d types, %d enums)\n",
			built.Version, len(built.Objects)+1, len(built.Enums))
		return nil
	}
	if err := writeGenerated(outputDir, files); err != nil {
		return err
	}
	// Verify what was just written, so a write run cannot report success while
	// leaving the tree in a state -check would reject.
	if err := checkGenerated(outputDir, files); err != nil {
		return err
	}
	fmt.Printf("generated %s from OCSF %s: %d types, %d enums\n",
		opts.OutputDir, built.Version, len(built.Objects)+1, len(built.Enums))
	return nil
}

func writeGenerated(dir string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	for _, name := range sortedNames(files) {
		if err := os.WriteFile(filepath.Join(dir, name), files[name], 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return removeStale(dir, files)
}

// removeStale deletes generated files this run no longer emits — an OCSF object
// dropped from the allowlist, or a change in how output is split across files.
// Left behind, such a file keeps compiling against a schema nothing regenerates
// it from, which is the failure -check exists to make impossible.
func removeStale(dir string, files map[string][]byte) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".generated.go") {
			continue
		}
		if _, expected := files[name]; expected {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			return fmt.Errorf("remove stale %s: %w", name, err)
		}
	}
	return nil
}

func checkGenerated(dir string, files map[string][]byte) error {
	var problems []string
	for _, name := range sortedNames(files) {
		existing, err := os.ReadFile(filepath.Join(dir, name))
		switch {
		case os.IsNotExist(err):
			problems = append(problems, name+" is missing")
		case err != nil:
			return fmt.Errorf("read %s: %w", name, err)
		case !bytes.Equal(existing, files[name]):
			problems = append(problems, name+" is stale")
		}
	}

	// A file the generator no longer emits is drift too: it would keep compiling
	// against a schema nothing regenerates it from.
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".generated.go") {
			continue
		}
		if _, expected := files[name]; !expected {
			problems = append(problems, name+" is no longer generated")
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("OCSF generated types drifted: %s; re-run `go run ./hack/gen-ocsf`",
			strings.Join(problems, "; "))
	}
	return nil
}

func sortedNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func refreshSchema(version, path string) error {
	client := &http.Client{Timeout: 2 * time.Minute}
	response, err := client.Get(fmt.Sprintf(exportURL, version))
	if err != nil {
		return fmt.Errorf("fetch OCSF %s schema export: %w", version, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch OCSF %s schema export: %s", version, response.Status)
	}
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("read OCSF %s schema export: %w", version, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create schema directory: %w", err)
	}
	return saveExport(path, raw)
}
