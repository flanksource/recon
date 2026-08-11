package nuclei

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/index"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	templatetypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	nucleiyaml "github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
)

// Template is one template, as the catalogue lists it.
//
// It carries nuclei's own metadata plus the fields that type deliberately omits
// — its source says so — because a browser showing only id, name and severity
// cannot answer "what does this actually check" or "how many requests will this
// cost".
type Template struct {
	*index.Metadata

	Description string   `json:"description,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	CVEID       string   `json:"cveId,omitempty"`
	CVSSScore   float64  `json:"cvssScore,omitempty"`

	// MaxRequests is what nuclei records as the template's request cost. It is
	// what lets a preview say how large a scan will be rather than only how many
	// templates it selected.
	MaxRequests int `json:"maxRequests,omitempty"`

	// Requires is what the template needs opted in before nuclei will load it.
	//
	// These are deliberately separate from ProtocolType. A template's type is
	// the first request block it declares, but its capabilities come from every
	// block: CVE-2022-42475 is an http template that also runs code, and reading
	// its requirements off its type would have a preview promise a template the
	// scan refuses.
	Requires Capabilities `json:"requires,omitzero"`
}

// Capabilities are the opt-in features a template needs to be loaded, mirroring
// nuclei's own capability set.
type Capabilities struct {
	Headless      bool `json:"headless,omitempty"`
	Code          bool `json:"code,omitempty"`
	File          bool `json:"file,omitempty"`
	SelfContained bool `json:"selfContained,omitempty"`
	Fuzzing       bool `json:"fuzzing,omitempty"`
}

// Index is every template on disk.
//
// It is a plain slice rather than nuclei's own index.Index: that one is an
// evicting cache sized against available memory, which is right for a scanner
// resolving templates it is about to run and wrong for a catalogue that must be
// able to say "13,686" and mean it.
type Index struct {
	Root      string
	Version   string
	Templates []Template
}

var (
	indexOnce  sync.Once
	indexCache *Index
	indexErr   error
	indexStamp time.Time
	indexMu    sync.Mutex
)

// LoadIndex reads every template under root.
//
// Cost is bounded and known: ~13,700 files and 35 MB, parsed in parallel and
// held in a few megabytes. Only the header of each template is decoded — its id,
// its info block and which protocol key it uses — so the request bodies, which
// are the bulk of the bytes, are never built into objects.
func LoadIndex(root string) (*Index, error) {
	if root == "" {
		return nil, fmt.Errorf("nuclei templates directory is not set")
	}
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf(
			"nuclei templates are not installed at %s: run `reconctl engine templates update`: %w", root, err)
	}

	paths, err := templatePaths(root)
	if err != nil {
		return nil, err
	}

	templates := make([]Template, len(paths))
	parseAll(paths, func(i int, template Template) { templates[i] = template })

	loaded := templates[:0]
	for _, template := range templates {
		// A file with no id is not a template — the directory also holds the
		// release's own metadata and the profile definitions.
		if template.Metadata != nil && template.ID != "" {
			loaded = append(loaded, template)
		}
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].FilePath < loaded[j].FilePath })

	return &Index{Root: root, Version: TemplateVersion(), Templates: loaded}, nil
}

// SharedIndex returns the process-wide index, building it once.
//
// It is rebuilt when the template release changes underneath it, which is the
// only thing that can invalidate it: templates are installed as a unit, and the
// checksum file is rewritten every time they are.
func SharedIndex() (*Index, error) {
	root := TemplatesDir()
	stamp := checksumStamp(root)

	indexMu.Lock()
	stale := indexCache != nil && !stamp.Equal(indexStamp)
	if stale {
		indexCache, indexErr = nil, nil
		indexOnce = sync.Once{}
	}
	indexMu.Unlock()

	indexOnce.Do(func() {
		loaded, err := LoadIndex(root)
		indexMu.Lock()
		indexCache, indexErr, indexStamp = loaded, err, stamp
		indexMu.Unlock()
	})

	indexMu.Lock()
	defer indexMu.Unlock()
	return indexCache, indexErr
}

// checksumStamp is when the installed template release was last written. A zero
// time means there is nothing installed to invalidate.
func checksumStamp(root string) time.Time {
	info, err := os.Stat(filepath.Join(root, "templates-checksum.txt"))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

func templatePaths(root string) ([]string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// .git holds every historical copy of every template, and the
			// profile directory holds scan configurations rather than templates.
			if name := entry.Name(); strings.HasPrefix(name, ".") || name == "profiles" {
				return fs.SkipDir
			}
			return nil
		}
		if ext := filepath.Ext(path); ext == ".yaml" || ext == ".yml" {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read nuclei templates at %s: %w", root, err)
	}
	return paths, nil
}

// parseAll decodes the templates across the available cores.
func parseAll(paths []string, collect func(int, Template)) {
	workers := min(runtime.NumCPU(), len(paths))
	if workers < 1 {
		return
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	queue := make(chan int)

	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range queue {
				template, ok := parseTemplate(paths[i])
				if !ok {
					continue
				}
				mu.Lock()
				collect(i, template)
				mu.Unlock()
			}
		}()
	}
	for i := range paths {
		queue <- i
	}
	close(queue)
	wg.Wait()
}

// header is the part of a template the catalogue needs.
//
// The protocol blocks are decoded as raw values because only their presence
// matters — it is how nuclei itself decides a template's type — and decoding
// their contents would mean building every matcher and extractor in the corpus
// to answer a question their presence already answers.
type header struct {
	ID   string     `yaml:"id"`
	Info model.Info `yaml:"info"`

	// SelfContained at the top level, and on individual requests below, is one
	// of the capabilities the loader refuses a template without.
	SelfContained bool `yaml:"self-contained"`

	// The request blocks nuclei inspects for capabilities are decoded as plain
	// maps; the rest only need to be counted. Either way the matchers and
	// extractors that make up the bulk of a template are never built.
	HTTP     []map[string]any `yaml:"http"`
	Requests []map[string]any `yaml:"requests"`
	Headless []map[string]any `yaml:"headless"`
	Network  []map[string]any `yaml:"network"`
	TCP      []map[string]any `yaml:"tcp"`

	DNS        []any `yaml:"dns"`
	File       []any `yaml:"file"`
	SSL        []any `yaml:"ssl"`
	WebSocket  []any `yaml:"websocket"`
	WHOIS      []any `yaml:"whois"`
	Code       []any `yaml:"code"`
	JavaScript []any `yaml:"javascript"`
	Workflows  []any `yaml:"workflows"`
}

// capabilities mirrors nuclei's capabilityDefinitions: what a template must have
// been opted into before the loader will accept it.
//
// Each is asked of every block the template declares, not of its type. A
// template that declares both http and code needs -code even though it is an
// http template.
func (h header) capabilities() Capabilities {
	caps := Capabilities{
		Headless:      len(h.Headless) > 0,
		Code:          len(h.Code) > 0,
		File:          len(h.File) > 0,
		SelfContained: h.SelfContained,
	}

	// Fuzzing is what -dast selects: nuclei's test is "any HTTP or headless
	// request configures fuzzing".
	for _, requests := range [][]map[string]any{h.HTTP, h.Requests, h.Headless} {
		for _, request := range requests {
			if _, ok := request["fuzzing"]; ok {
				caps.Fuzzing = true
			}
		}
	}
	for _, requests := range [][]map[string]any{h.HTTP, h.Requests, h.Network, h.TCP} {
		for _, request := range requests {
			if enabled, ok := request["self-contained"].(bool); ok && enabled {
				caps.SelfContained = true
			}
		}
	}
	return caps
}

func parseTemplate(path string) (Template, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Template{}, false
	}

	// nuclei's own wrapper, not gopkg.in/yaml.v3 directly: the info block's
	// types implement the yaml.v2 unmarshaller shape, which only this decoder
	// still honours. Decoding without it silently loses tags and severity.
	var decoded header
	if err := nucleiyaml.Unmarshal(data, &decoded); err != nil {
		return Template{}, false
	}
	if decoded.ID == "" {
		return Template{}, false
	}

	info, err := os.Stat(path)
	if err != nil {
		return Template{}, false
	}

	metadata := &index.Metadata{
		ID:           decoded.ID,
		FilePath:     path,
		ModTime:      info.ModTime(),
		Name:         decoded.Info.Name,
		Authors:      decoded.Info.Authors.ToSlice(),
		Tags:         decoded.Info.Tags.ToSlice(),
		Severity:     decoded.Info.SeverityHolder.Severity.String(),
		ProtocolType: decoded.protocol().String(),
	}

	template := Template{
		Metadata:    metadata,
		Description: decoded.Info.Description,
		Remediation: decoded.Info.Remediation,
		MaxRequests: maxRequests(decoded.Info.Metadata),
		Requires:    decoded.capabilities(),
	}
	if decoded.Info.Reference != nil {
		template.Reference = decoded.Info.Reference.ToSlice()
	}
	if classification := decoded.Info.Classification; classification != nil {
		template.CVEID = classification.CVEID.String()
		template.CVSSScore = classification.CVSSScore
	}
	return template, true
}

// protocol mirrors Template.Type: the first request block present wins, in
// nuclei's own order.
func (h header) protocol() templatetypes.ProtocolType {
	switch {
	case len(h.DNS) > 0:
		return templatetypes.DNSProtocol
	case len(h.File) > 0:
		return templatetypes.FileProtocol
	case len(h.HTTP) > 0 || len(h.Requests) > 0:
		return templatetypes.HTTPProtocol
	case len(h.Headless) > 0:
		return templatetypes.HeadlessProtocol
	case len(h.Network) > 0 || len(h.TCP) > 0:
		return templatetypes.NetworkProtocol
	case len(h.SSL) > 0:
		return templatetypes.SSLProtocol
	case len(h.WebSocket) > 0:
		return templatetypes.WebsocketProtocol
	case len(h.WHOIS) > 0:
		return templatetypes.WHOISProtocol
	case len(h.Code) > 0:
		return templatetypes.CodeProtocol
	case len(h.JavaScript) > 0:
		return templatetypes.JavascriptProtocol
	case len(h.Workflows) > 0:
		return templatetypes.WorkflowProtocol
	default:
		return templatetypes.InvalidProtocol
	}
}

// maxRequests reads the request cost nuclei records on most templates.
func maxRequests(metadata map[string]any) int {
	switch value := metadata["max-request"].(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		return 0
	}
}
