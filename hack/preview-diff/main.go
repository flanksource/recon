// Command preview-diff reports where the template preview and nuclei's own
// loader disagree for a given configuration.
//
//	go run ./hack/preview-diff '{"type":["dns"]}'
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"

	"github.com/flanksource/recon/internal/engines/scan/nuclei"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: preview-diff '<config json>'")
	}

	var config map[string]any
	if err := json.Unmarshal([]byte(os.Args[1]), &config); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	index, err := nuclei.SharedIndex()
	if err != nil {
		return err
	}
	selected := index.Select(config)

	opts, err := nuclei.Options(config)
	if err != nil {
		return err
	}
	engine, err := nucleilib.NewNucleiEngineCtx(context.Background(), nucleilib.WithOptions(opts))
	if err != nil {
		return err
	}
	defer engine.Close()
	if err := engine.LoadAllTemplates(); err != nil {
		return err
	}

	loaded := map[string]bool{}
	for _, template := range engine.GetTemplates() {
		loaded[template.Path] = true
	}
	matched := map[string]bool{}
	for _, template := range selected {
		matched[template.FilePath] = true
	}

	fmt.Printf("preview=%d loader=%d\n", len(selected), len(loaded))
	report("only in preview", matched, loaded)
	report("only in loader", loaded, matched)
	return nil
}

func report(label string, left, right map[string]bool) {
	var only []string
	for path := range left {
		if !right[path] {
			only = append(only, path)
		}
	}
	sort.Strings(only)
	fmt.Printf("%s (%d):\n", label, len(only))
	for _, path := range only {
		fmt.Println("  ", path)
	}
}
