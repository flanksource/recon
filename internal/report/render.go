// Package report prints a scan as a document.
//
// Rendering is delegated to the facet CLI, which compiles the embedded React
// template and prints it through headless Chromium. That is deliberately not
// reimplemented here: the template is the same file the in-app report playground
// mounts, so what the browser previews and what the PDF contains cannot drift,
// and the one thing Go contributes is the payload.
//
// When FACET_URL is set the CLI forwards the render to a facet server instead of
// running the pipeline locally. Nothing here needs to know which happened.
package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	recon "github.com/flanksource/recon"
)

// Format is what facet is asked to produce.
type Format string

const (
	FormatPDF  Format = "pdf"
	FormatHTML Format = "html"
)

// ParseFormat resolves a caller-supplied format name.
func ParseFormat(value string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(value))) {
	case FormatPDF, "":
		return FormatPDF, nil
	case FormatHTML:
		return FormatHTML, nil
	default:
		return "", fmt.Errorf("unsupported report format %q: want pdf or html", value)
	}
}

// ContentType is what the rendered bytes should be served as.
func (f Format) ContentType() string {
	if f == FormatHTML {
		return "text/html; charset=utf-8"
	}
	return "application/pdf"
}

// DefaultTimeout bounds one render. A cold run installs the template's
// dependencies and starts Chromium before it prints anything, so the bound is
// generous — it exists to stop a wedged renderer holding a request open forever,
// not to police a slow one.
const DefaultTimeout = 5 * time.Minute

// ErrRendererUnavailable is returned when no facet binary can be found. It is a
// distinct error because it is the caller's environment rather than their
// request: the API answers it as 501 and the UI says how to fix it.
var ErrRendererUnavailable = errors.New("facet is not installed")

// Options configures a Renderer.
type Options struct {
	// SourceDir renders from a template directory on disk instead of the copy
	// embedded in the binary. It is what makes the report designable: point it
	// at app/reports in a checkout and an edit to the TSX is in the next PDF.
	SourceDir string

	// Timeout bounds one render. Zero means DefaultTimeout.
	Timeout time.Duration
}

// Renderer prints report payloads through facet.
type Renderer struct {
	sourceDir string
	timeout   time.Duration

	extractOnce sync.Once
	extracted   string
	extractErr  error
}

// New builds a renderer.
func New(options Options) *Renderer {
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Renderer{sourceDir: options.SourceDir, timeout: timeout}
}

// Available reports whether a render could run at all, so a caller can say
// "install facet" once rather than failing every export with a stack trace.
func (r *Renderer) Available() error {
	if _, err := exec.LookPath("facet"); err != nil {
		return fmt.Errorf("%w: install it with `npm install -g @flanksource/facet-cli`, or point FACET_URL at a facet server", ErrRendererUnavailable)
	}
	return nil
}

// Render prints payload and returns the document.
func (r *Renderer) Render(ctx context.Context, format Format, payload any) ([]byte, error) {
	if err := r.Available(); err != nil {
		return nil, err
	}
	source, err := r.source()
	if err != nil {
		return nil, err
	}

	workDir, err := os.MkdirTemp("", "recon-report-*")
	if err != nil {
		return nil, fmt.Errorf("create report work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	dataFile := filepath.Join(workDir, "report.json")
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode report payload: %w", err)
	}
	if err := os.WriteFile(dataFile, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write report payload: %w", err)
	}
	outFile := filepath.Join(workDir, "report."+string(format))

	renderCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var stdout, stderr bytes.Buffer
	command := exec.CommandContext(renderCtx, "facet", string(format), recon.ReportEntry,
		"-d", dataFile, "-o", outFile)
	command.Dir = source
	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if errors.Is(renderCtx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("facet %s timed out after %s", format, r.timeout)
		}
		return nil, renderError(format, err, stdout.String(), stderr.String())
	}

	rendered, err := os.ReadFile(outFile)
	if err != nil {
		return nil, fmt.Errorf("read rendered report: %w", err)
	}
	if len(rendered) == 0 {
		return nil, fmt.Errorf("facet %s produced an empty document", format)
	}
	return rendered, nil
}

// source resolves the template directory, extracting the embedded copy once.
func (r *Renderer) source() (string, error) {
	if r.sourceDir != "" {
		if _, err := os.Stat(filepath.Join(r.sourceDir, recon.ReportEntry)); err != nil {
			return "", fmt.Errorf("report source %s has no %s: %w", r.sourceDir, recon.ReportEntry, err)
		}
		return r.sourceDir, nil
	}
	r.extractOnce.Do(func() { r.extracted, r.extractErr = ExtractEmbedded() })
	return r.extracted, r.extractErr
}

// ExtractEmbedded writes the embedded template to a cache directory named for
// its own contents and returns the path.
//
// Content-addressed so an upgraded binary never renders from the previous
// build's template: the directory name changes with the source, and the stale
// one is simply never opened again. facet keeps its dependency cache in a
// .facet/ subdirectory, so reusing the directory across renders is what makes
// every render after the first a warm one.
func ExtractEmbedded() (string, error) {
	files, err := embeddedFiles()
	if err != nil {
		return "", err
	}

	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "recon", "report-"+fingerprint(files))
	entry := filepath.Join(dir, recon.ReportEntry)
	if _, err := os.Stat(entry); err == nil {
		return dir, nil
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create report cache dir: %w", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			return "", fmt.Errorf("extract report template %s: %w", name, err)
		}
	}
	return dir, nil
}

// embeddedFiles reads the template out of the binary, keyed by base name.
func embeddedFiles() (map[string][]byte, error) {
	entries, err := fs.ReadDir(recon.ReportSource, recon.ReportSourceDir)
	if err != nil {
		return nil, fmt.Errorf("read embedded report template: %w", err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := recon.ReportSource.ReadFile(path.Join(recon.ReportSourceDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read embedded report template %s: %w", entry.Name(), err)
		}
		files[entry.Name()] = content
	}
	if _, ok := files[recon.ReportEntry]; !ok {
		return nil, fmt.Errorf("embedded report template has no %s", recon.ReportEntry)
	}
	return files, nil
}

// fingerprint is a stable digest of the template, so the cache directory changes
// whenever any file in it does.
func fingerprint(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)

	digest := sha256.New()
	for _, name := range names {
		_, _ = io.WriteString(digest, name)
		_, _ = digest.Write(files[name])
	}
	return hex.EncodeToString(digest.Sum(nil))[:16]
}

func renderError(format Format, err error, stdout, stderr string) error {
	var sections []string
	for _, stream := range []struct{ label, text string }{{"stdout", stdout}, {"stderr", stderr}} {
		if strings.TrimSpace(stream.text) != "" {
			sections = append(sections, stream.label+":\n"+strings.TrimRight(stream.text, "\n"))
		}
	}
	if len(sections) == 0 {
		return fmt.Errorf("facet %s failed: %w", format, err)
	}
	return fmt.Errorf("facet %s failed: %w\n%s", format, err, strings.Join(sections, "\n\n"))
}
