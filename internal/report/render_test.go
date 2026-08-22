package report_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	recon "github.com/flanksource/recon"
	"github.com/flanksource/recon/internal/report"
)

func TestReport(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "report")
}

// fakeFacet puts an executable named `facet` on PATH that echoes back what it
// was asked to render. It is what makes the command wiring testable: the real
// binary needs Node, a dependency install and Chromium, none of which belong in
// a unit test, but the argument order and the working directory are exactly the
// parts that break silently.
func fakeFacet(script string) {
	GinkgoHelper()
	dir := GinkgoT().TempDir()
	path := filepath.Join(dir, "facet")
	Expect(os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700)).To(Succeed())
	GinkgoT().Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// recordingFacet writes its own invocation, then copies the payload to the
// output path so the renderer has something to read back.
const recordingFacet = `
printf '%s\n' "$PWD" > "$(dirname "$0")/cwd"
printf '%s\n' "$@" > "$(dirname "$0")/args"
format="$1"; shift
data=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -d) data="$2"; shift 2;;
    -o) out="$2"; shift 2;;
    *) shift;;
  esac
done
printf 'rendered %s from ' "$format" > "$out"
cat "$data" >> "$out"
`

var _ = Describe("choosing a report format", func() {
	DescribeTable("parsing what the caller asked for",
		func(input string, expected report.Format) {
			format, err := report.ParseFormat(input)
			Expect(err).ToNot(HaveOccurred())
			Expect(format).To(Equal(expected))
		},
		Entry("pdf", "pdf", report.FormatPDF),
		Entry("html", "html", report.FormatHTML),
		Entry("uppercase", "PDF", report.FormatPDF),
		Entry("nothing, which is a PDF", "", report.FormatPDF),
	)

	It("rejects a format facet cannot produce here", func() {
		_, err := report.ParseFormat("docx")
		Expect(err).To(MatchError(ContainSubstring("unsupported report format")))
	})

	It("serves each format as its own content type", func() {
		Expect(report.FormatPDF.ContentType()).To(Equal("application/pdf"))
		Expect(report.FormatHTML.ContentType()).To(Equal("text/html; charset=utf-8"))
	})
})

var _ = Describe("the embedded template", func() {
	It("carries the entry file and every module it imports", func() {
		dir, err := report.ExtractEmbedded()
		Expect(err).ToNot(HaveOccurred())

		for _, name := range []string{
			recon.ReportEntry,
			"scan-report-sections.tsx",
			"scan-report-model.ts",
			"scan-report-types.ts",
			"package.json",
		} {
			Expect(filepath.Join(dir, name)).To(BeAnExistingFile(), "embed.go must ship %s", name)
		}
	})

	It("extracts to a directory named for its own contents, so an upgrade cannot render from the last build", func() {
		dir, err := report.ExtractEmbedded()
		Expect(err).ToNot(HaveOccurred())

		again, err := report.ExtractEmbedded()
		Expect(err).ToNot(HaveOccurred())
		Expect(again).To(Equal(dir))

		entry, err := os.ReadFile(filepath.Join(dir, recon.ReportEntry))
		Expect(err).ToNot(HaveOccurred())
		Expect(string(entry)).To(ContainSubstring("export default function ScanReport"))
		Expect(filepath.Base(dir)).To(HavePrefix("report-"))
	})
})

var _ = Describe("rendering a report", func() {
	var renderer *report.Renderer
	var source string

	BeforeEach(func() {
		source = GinkgoT().TempDir()
		Expect(os.WriteFile(filepath.Join(source, recon.ReportEntry), []byte("export default () => null"), 0o600)).
			To(Succeed())
		renderer = report.New(report.Options{SourceDir: source})
	})

	It("runs facet in the template directory with the payload on disk", func() {
		fakeFacet(recordingFacet)

		document, err := renderer.Render(context.Background(), report.FormatPDF,
			map[string]any{"scan": map[string]any{"name": "nuclei-safe-1"}})

		Expect(err).ToNot(HaveOccurred())
		Expect(string(document)).To(HavePrefix("rendered pdf from "))

		var payload map[string]any
		Expect(json.Unmarshal([]byte(strings.TrimPrefix(string(document), "rendered pdf from ")), &payload)).
			To(Succeed())
		Expect(payload).To(HaveKeyWithValue("scan", HaveKeyWithValue("name", "nuclei-safe-1")))
	})

	It("names the template as the entry file and runs from the template directory", func() {
		fakeFacet(recordingFacet)

		_, err := renderer.Render(context.Background(), report.FormatHTML, map[string]any{})
		Expect(err).ToNot(HaveOccurred())

		path, err := exec.LookPath("facet")
		Expect(err).ToNot(HaveOccurred())
		recorded := func(name string) string {
			GinkgoHelper()
			content, err := os.ReadFile(filepath.Join(filepath.Dir(path), name))
			Expect(err).ToNot(HaveOccurred())
			return string(content)
		}

		Expect(strings.Fields(recorded("args"))).To(ContainElements("html", recon.ReportEntry))
		Expect(strings.TrimSpace(recorded("cwd"))).To(HaveSuffix(filepath.Base(source)))
	})

	It("carries facet's own output into the error when a render fails", func() {
		fakeFacet(`echo "Unexpected token" >&2; exit 1`)

		_, err := renderer.Render(context.Background(), report.FormatPDF, map[string]any{})

		Expect(err).To(MatchError(ContainSubstring("facet pdf failed")))
		Expect(err).To(MatchError(ContainSubstring("Unexpected token")))
	})

	It("rejects an empty document rather than serving a zero-byte PDF", func() {
		fakeFacet(`while [ $# -gt 0 ]; do case "$1" in -o) : > "$2"; shift 2;; *) shift;; esac; done`)

		_, err := renderer.Render(context.Background(), report.FormatPDF, map[string]any{})

		Expect(err).To(MatchError(ContainSubstring("empty document")))
	})

	It("says how to install facet when it is not on PATH", func() {
		GinkgoT().Setenv("PATH", GinkgoT().TempDir())

		Expect(renderer.Available()).To(MatchError(report.ErrRendererUnavailable))
		Expect(renderer.Available()).To(MatchError(ContainSubstring("@flanksource/facet-cli")))

		_, err := renderer.Render(context.Background(), report.FormatPDF, map[string]any{})
		Expect(err).To(MatchError(report.ErrRendererUnavailable))
	})

	It("refuses a source directory that holds no template", func() {
		fakeFacet(recordingFacet)
		empty := report.New(report.Options{SourceDir: GinkgoT().TempDir()})

		_, err := empty.Render(context.Background(), report.FormatPDF, map[string]any{})

		Expect(err).To(MatchError(ContainSubstring(recon.ReportEntry)))
	})
})
