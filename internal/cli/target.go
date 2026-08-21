package cli

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/flanksource/clicky/entity"
	"github.com/spf13/cobra"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/store"
)

// registerTargetCommands attaches the bulk operations to the generated `target`
// entity command. Importing is an action on the inventory, not a resource of
// its own — the same reasoning that puts `install` under `engine`.
//
// A subcommand registered this way stays on the CLI: the generated HTTP surface
// serves an entity's verbs, and a route that read a path off the request would
// let a caller read the server's filesystem.
func registerTargetCommands() {
	entity.RegisterSubCommand("target", newTargetImportCommand())
}

func newTargetImportCommand() *cobra.Command {
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "import <path>",
		Short: "Add or update targets from files",
		Long: "Reads target documents from a directory of .json files or from a single file\n" +
			"holding one document or an array of them, and applies their curated fields to\n" +
			"the inventory.\n\n" +
			"Curated fields and mutable provider context configuration only: the observed,\n" +
			"network, http, tech, tls and scan sections are discovery's output, so an import\n" +
			"neither writes nor clears them. Re-running\n" +
			"an import changes nothing, and a file that fails validation halfway through\n" +
			"leaves the inventory untouched rather than half-applied.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targets, err := readTargets(args[0])
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				return fmt.Errorf("%s holds no target documents", args[0])
			}

			if dryRun {
				cmd.Printf("%d target(s) read from %s; --dry-run, nothing written\n",
					len(targets), args[0])
				return nil
			}

			st, err := registry.Store()
			if err != nil {
				return err
			}
			result, err := st.ImportTargets(cmd.Context(), targets)
			if err != nil {
				return err
			}
			printImport(cmd, result)
			return nil
		},
	}

	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"parse and report what would be imported without writing anything")
	return cmd
}

func printImport(cmd *cobra.Command, result store.ImportResult) {
	cmd.Printf("%d created, %d updated, %d unchanged\n",
		len(result.Created), len(result.Updated), len(result.Unchanged))
	for _, host := range result.Created {
		cmd.Printf("  + %s\n", host)
	}
	for _, host := range result.Updated {
		cmd.Printf("  ~ %s\n", host)
	}
}

// readTargets loads target definitions from a directory of documents or from a
// single file holding one document or an array of them.
func readTargets(path string) ([]api.NewTarget, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !info.IsDir() {
		return decodeTargets(path)
	}

	entries, err := fs.Glob(os.DirFS(path), "*.json")
	if err != nil {
		return nil, err
	}
	// Sorted so a failure reports the same document every run, and so the
	// created/updated lists are diffable between imports.
	sort.Strings(entries)

	var targets []api.NewTarget
	for _, entry := range entries {
		decoded, err := decodeTargets(filepath.Join(path, entry))
		if err != nil {
			return nil, err
		}
		targets = append(targets, decoded...)
	}
	return targets, nil
}

// decodeTargets reads one file, which holds either a single document or an
// array of them.
func decodeTargets(path string) ([]api.NewTarget, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var bodies []map[string]any
	if err := decodeOneOrMany(raw, &bodies); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	targets := make([]api.NewTarget, 0, len(bodies))
	for _, body := range bodies {
		target, err := api.TargetFrom(definitionOnly(body))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func decodeOneOrMany(raw []byte, into *[]map[string]any) error {
	if strings.HasPrefix(strings.TrimSpace(string(raw)), "[") {
		return json.Unmarshal(raw, into)
	}
	var single map[string]any
	if err := json.Unmarshal(raw, &single); err != nil {
		return err
	}
	*into = []map[string]any{single}
	return nil
}

// definitionOnly drops the fields an import is not entitled to set.
//
// The documents this reads are whole target documents — the shape the API
// returns — so they carry discovery's observations and the schema stamps. A
// create refuses all of those, and rightly: an import that wrote them would be
// recording that something saw a host answer when nothing did. Dropping them
// here is what lets a document the API produced be fed straight back in.
func definitionOnly(body map[string]any) map[string]any {
	skip := map[string]bool{
		"$schema": true, "version": true,
		"observed": true, "network": true, "http": true,
		"tech": true, "tls": true, "scan": true,
	}
	kept := make(map[string]any, len(body))
	for key, value := range body {
		if key == "credentials" && hasConfiguredCredential(value) {
			continue
		}
		if !skip[key] {
			kept[key] = value
		}
	}
	return kept
}

func hasConfiguredCredential(value any) bool {
	switch value := value.(type) {
	case map[string]any:
		if configured, ok := value["configured"].(bool); ok && configured {
			return true
		}
		for _, child := range value {
			if hasConfiguredCredential(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if hasConfiguredCredential(child) {
				return true
			}
		}
	}
	return false
}
