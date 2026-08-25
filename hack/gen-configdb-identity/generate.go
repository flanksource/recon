package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Options struct {
	RepositoryRoot string
	SourceDir      string
	Check          bool
}

// catalogue is everything read out of config-db, in the order the generated file
// declares it.
type catalogue struct {
	GCPOverrides map[string]string
	AWSTypes     []string
	GitHubTypes  []string
	ScraperLess  []string
}

const generatedPath = "internal/configdb/types.generated.go"

func Generate(options Options) error {
	source := options.SourceDir
	if !filepath.IsAbs(source) {
		source = filepath.Join(options.RepositoryRoot, source)
	}
	if _, err := os.Stat(source); err != nil {
		return fmt.Errorf("pinned config-db source is not available at %s: %w\n"+
			"add it with: git submodule add --depth 1 https://github.com/flanksource/config-db third_party/config-db\n"+
			"or point --source at a local checkout", source, err)
	}

	read, err := readCatalogue(source)
	if err != nil {
		return err
	}
	rendered, err := render(read)
	if err != nil {
		return err
	}

	target := filepath.Join(options.RepositoryRoot, generatedPath)
	if options.Check {
		existing, err := os.ReadFile(target)
		if err != nil {
			return fmt.Errorf("read %s: %w", generatedPath, err)
		}
		if !bytes.Equal(existing, rendered) {
			return fmt.Errorf("%s has drifted from config-db; re-run `go run ./hack/gen-configdb-identity`", generatedPath)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(generatedPath), err)
	}
	return os.WriteFile(target, rendered, 0o644)
}

func readCatalogue(source string) (catalogue, error) {
	var read catalogue
	var err error

	// The GCP disambiguation table. It is the whole reason this generator
	// exists: ~120 entries that no rule predicts, keyed by the same Cloud Asset
	// Inventory type Prowler reports.
	read.GCPOverrides, err = stringMap(filepath.Join(source, "scrapers/gcp/types.go"), "typeOverrides")
	if err != nil {
		return catalogue{}, err
	}

	// config-db uses AWS Config's own resource types verbatim, declared as
	// constants. Read as a vocabulary rather than a mapping: recon recognises a
	// type that is already one, and declines anything else.
	read.AWSTypes, err = constantValues(filepath.Join(source, "api/v1/aws.go"), func(value string) bool {
		return strings.HasPrefix(value, "AWS::")
	})
	if err != nil {
		return catalogue{}, err
	}

	// `::` is what separates a config type from the relationship names declared
	// beside it — GitHubOrganizationRepository is an edge, GitHub::Repository is
	// a config item, and both are string constants starting with "GitHub".
	isGitHubType := func(value string) bool {
		return strings.HasPrefix(value, "GitHub") && strings.Contains(value, "::")
	}
	read.GitHubTypes, err = constantValues(filepath.Join(source, "api/v1/github.go"), isGitHubType)
	if err != nil {
		return catalogue{}, err
	}
	// The rest of the GitHub vocabulary lives in the scraper rather than in the
	// api package, so both are read; a type declared in only one of them would
	// otherwise be silently missing from the lookup.
	for _, companion := range []string{"scrapers/github/scraper.go", "scrapers/github/workflows.go"} {
		declared, err := constantValues(filepath.Join(source, companion), isGitHubType)
		if err != nil {
			return catalogue{}, err
		}
		read.GitHubTypes = merge(read.GitHubTypes, declared)
	}

	// The types config-db stores with no scraper. A lookup that scoped by
	// scraper for one of these would exclude the rows it is looking for.
	read.ScraperLess, err = sliceValues(filepath.Join(source, "api/v1/common.go"), "ScraperLessTypes",
		filepath.Join(source, "api/v1/aws.go"), filepath.Join(source, "api/v1/github.go"))
	if err != nil {
		return catalogue{}, err
	}

	if len(read.GCPOverrides) == 0 || len(read.AWSTypes) == 0 {
		return catalogue{}, fmt.Errorf("config-db source at %s yielded no vocabularies; the layout has moved", source)
	}
	return read, nil
}

// stringMap reads a package-level `var name = map[string]string{...}` literal.
func stringMap(path, name string) (map[string]string, error) {
	file, err := parseFile(path)
	if err != nil {
		return nil, err
	}

	values := map[string]string{}
	found := false
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != name || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			found = true
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, keyOK := stringLiteral(pair.Key)
				mapped, valueOK := stringLiteral(pair.Value)
				if keyOK && valueOK {
					values[key] = mapped
				}
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("%s declares no %s map", path, name)
	}
	return values, nil
}

// constantValues reads every string constant in a file whose value satisfies
// keep. Values rather than names, because the name is config-db's business and
// the value is the vocabulary.
func constantValues(path string, keep func(string) bool) ([]string, error) {
	file, err := parseFile(path)
	if err != nil {
		return nil, err
	}

	var values []string
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, expr := range value.Values {
				if literal, ok := stringLiteral(expr); ok && keep(literal) {
					values = append(values, literal)
				}
			}
		}
	}
	return merge(nil, values), nil
}

// sliceValues reads a `var name = []string{A, B, C}` whose elements are
// identifiers declared as constants in the companion files.
func sliceValues(path, name string, companions ...string) ([]string, error) {
	file, err := parseFile(path)
	if err != nil {
		return nil, err
	}

	constants := map[string]string{}
	for _, companion := range append(companions, path) {
		declared, err := namedConstants(companion)
		if err != nil {
			return nil, err
		}
		for key, value := range declared {
			constants[key] = value
		}
	}

	var values []string
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != name || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, element := range literal.Elts {
				switch resolved := element.(type) {
				case *ast.Ident:
					if constant, known := constants[resolved.Name]; known {
						values = append(values, constant)
					}
				case *ast.BasicLit:
					if constant, ok := stringLiteral(resolved); ok {
						values = append(values, constant)
					}
				}
			}
		}
	}
	return merge(nil, values), nil
}

func namedConstants(path string) (map[string]string, error) {
	file, err := parseFile(path)
	if err != nil {
		return nil, err
	}

	constants := map[string]string{}
	for _, decl := range file.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, spec := range general.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Values) != len(value.Names) {
				continue
			}
			for index, ident := range value.Names {
				if literal, ok := stringLiteral(value.Values[index]); ok {
					constants[ident.Name] = literal
				}
			}
		}
	}
	return constants, nil
}

func parseFile(path string) (*ast.File, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return file, nil
}

func stringLiteral(expr ast.Expr) (string, bool) {
	literal, ok := expr.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	unquoted, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return unquoted, true
}

func merge(into, values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(into)+len(values))
	for _, value := range append(append([]string{}, into...), values...) {
		if value == "" {
			continue
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
