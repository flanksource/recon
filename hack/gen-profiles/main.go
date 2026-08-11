// Command gen-profiles turns nuclei's community scan profiles into Go.
//
//	go run ./hack/gen-profiles
//
// The profiles that ship with nuclei-templates are flag maps in exactly the
// shape a recon profile's config already is, so they are imported rather than
// referenced: a profile someone can open, read and edit is worth more than an
// opaque -profile name pointing at a file outside the repo.
//
// Generated rather than hand-copied because there are twenty of them and they
// change with each templates release, and because a typo in a tag produces a
// profile that silently selects nothing.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	nucleiyaml "github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"

	"github.com/flanksource/recon/internal/engines/scan/nuclei"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type profile struct {
	Name    string
	Comment string
	Config  nucleiyaml.MapSlice
}

func run() error {
	root, err := moduleRoot()
	if err != nil {
		return err
	}

	dir := filepath.Join(nuclei.TemplatesDir(), "profiles")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read %s: %w (run `reconctl engine templates update` first)", dir, err)
	}

	var profiles []profile
	for _, entry := range entries {
		if entry.IsDir() || (filepath.Ext(entry.Name()) != ".yml" && filepath.Ext(entry.Name()) != ".yaml") {
			continue
		}
		loaded, err := readProfile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return err
		}
		if err := repair(&loaded); err != nil {
			return err
		}
		profiles = append(profiles, loaded)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

	source, err := render(profiles)
	if err != nil {
		return err
	}

	target := filepath.Join(root, "internal/engines/scan/nuclei/profiles_generated.go")
	if err := os.WriteFile(target, source, 0o644); err != nil {
		return err
	}
	fmt.Printf("%d community profiles -> internal/engines/scan/nuclei/profiles_generated.go\n", len(profiles))
	return nil
}

func readProfile(path string) (profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return profile{}, err
	}

	// A map slice rather than a map: key order is the order the upstream author
	// wrote them, and it is what makes the generated file readable.
	var config nucleiyaml.MapSlice
	if err := nucleiyaml.Unmarshal(data, &config); err != nil {
		return profile{}, fmt.Errorf("parse %s: %w", path, err)
	}

	name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".yml"), ".yaml")
	return profile{Name: name, Comment: leadingComment(data), Config: config}, nil
}

// repair makes an imported profile select something.
//
// Several of nuclei's cloud profiles target templates that declare
// self-contained requests but never enable them, so on their own they select no
// templates at all. That is fine upstream, where the flag comes from the command
// line; here it would seed a profile that runs nothing and reports a clean scan.
//
// The correction is computed against the installed corpus rather than hardcoded,
// so it stays right as the templates change — and the "every profile selects
// something" test fails loudly if a future release needs a different one.
func repair(item *profile) error {
	index, err := nuclei.SharedIndex()
	if err != nil {
		return err
	}
	if index.Match(configMap(item.Config)).Total > 0 {
		return nil
	}

	const key = "enable-self-contained"
	widened := configMap(item.Config)
	widened[key] = true
	if index.Match(widened).Total == 0 {
		return nil
	}

	item.Config = append(item.Config, nucleiyaml.MapItem{Key: key, Value: true})
	item.Comment = strings.TrimRight(item.Comment, "\n") +
		"\n\nSelf-contained templates are enabled because every template this profile" +
		"\nselects declares one; without it the profile runs nothing."
	return nil
}

// configMap flattens the ordered config for matching.
func configMap(config nucleiyaml.MapSlice) map[string]any {
	flat := make(map[string]any, len(config))
	for _, entry := range config {
		if key, ok := entry.Key.(string); ok {
			flat[key] = entry.Value
		}
	}
	return flat
}

// leadingComment is the file's own description, kept so an imported profile
// still explains itself. The "run it like this" lines are dropped: they name a
// nuclei command that is not how recon runs anything.
func leadingComment(data []byte) string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			break
		}
		text := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		if text == "" || strings.HasPrefix(text, "=") {
			continue
		}
		lower := strings.ToLower(text)
		if strings.HasPrefix(lower, "nuclei -") || strings.HasPrefix(lower, "you can run") ||
			strings.HasPrefix(lower, "running this profile") || lower == "purpose:" {
			continue
		}
		lines = append(lines, text)
	}
	return strings.Join(lines, "\n")
}

func render(profiles []profile) ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(`// Code generated by hack/gen-profiles. DO NOT EDIT.
//
// Regenerate with:
//	go run ./hack/gen-profiles

package nuclei

import "github.com/flanksource/recon/internal/engines"

// communityProfiles are nuclei's own scan profiles, imported from the templates
// release. They are ordinary profiles here: previewable, editable, and validated
// against the same option catalog as everything else.
//
// They are snapshots. Re-run the generator after updating templates.
var communityProfiles = []engines.DefaultProfile{
`)

	for _, item := range profiles {
		out.WriteString("\t{\n")
		fmt.Fprintf(&out, "\t\tName: %s,\n", strconv.Quote(item.Name))
		if item.Comment != "" {
			fmt.Fprintf(&out, "\t\tComment: %s,\n", quoteLines(item.Comment))
		}
		out.WriteString("\t\tConfig: map[string]any{\n")
		for _, entry := range item.Config {
			key, ok := entry.Key.(string)
			if !ok {
				return nil, fmt.Errorf("profile %s: non-string key %v", item.Name, entry.Key)
			}
			value, err := renderValue(entry.Value)
			if err != nil {
				return nil, fmt.Errorf("profile %s, key %s: %w", item.Name, key, err)
			}
			fmt.Fprintf(&out, "\t\t\t%s: %s,\n", strconv.Quote(key), value)
		}
		out.WriteString("\t\t},\n\t},\n")
	}
	out.WriteString("}\n")

	source, err := format.Source(out.Bytes())
	if err != nil {
		return nil, fmt.Errorf("format generated source: %w", err)
	}
	return source, nil
}

func renderValue(value any) (string, error) {
	switch typed := value.(type) {
	case bool:
		return strconv.FormatBool(typed), nil
	case int:
		return strconv.Itoa(typed), nil
	case string:
		return strconv.Quote(typed), nil
	case []any:
		items := make([]string, 0, len(typed))
		for _, item := range typed {
			text, ok := item.(string)
			if !ok {
				return "", fmt.Errorf("expected a list of strings, got a %T element", item)
			}
			items = append(items, strconv.Quote(text))
		}
		return "[]any{" + strings.Join(items, ", ") + "}", nil
	default:
		return "", fmt.Errorf("unsupported value type %T", value)
	}
}

// quoteLines renders a multi-line comment as concatenated Go string literals,
// so the generated source stays readable rather than one enormous line.
func quoteLines(text string) string {
	lines := strings.Split(text, "\n")
	quoted := make([]string, 0, len(lines))
	for i, line := range lines {
		if i < len(lines)-1 {
			line += "\n"
		}
		quoted = append(quoted, strconv.Quote(line))
	}
	return strings.Join(quoted, " +\n\t\t\t")
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}
