package api_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

// The report payload crosses a language boundary: Go marshals it and a React
// template compiled by facet reads it. Nothing at build time links the two, so
// these specs are the link — they pin the JSON this emits against the field
// names app/reports/scan-report-types.ts declares.
//
// A rename on either side fails here rather than printing a report with a blank
// section, which is the failure mode this exists to prevent: a missing key in
// JavaScript is `undefined`, not an error.

func keys(value any) []string {
	GinkgoHelper()
	encoded, err := json.Marshal(value)
	Expect(err).ToNot(HaveOccurred())

	var decoded map[string]json.RawMessage
	Expect(json.Unmarshal(encoded, &decoded)).To(Succeed())

	names := make([]string, 0, len(decoded))
	for name := range decoded {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// templateContract reads the field names one type in the template's input
// contract declares, so the assertion is against the actual TypeScript rather
// than a copy of it that could drift alongside.
//
// The field pattern is anchored to the two-space indentation of a top-level
// member, which is what keeps a JSDoc line and a nested type out of the result.
func templateContract(typeName string) []string {
	GinkgoHelper()
	source, err := os.ReadFile(filepath.Join("..", "..", "app", "reports", "scan-report-types.ts"))
	Expect(err).ToNot(HaveOccurred(), "the template's input contract must be readable from the api package")

	block := regexp.MustCompile(`(?s)export type ` + typeName + ` = \{(.*?)\n\};`).FindStringSubmatch(string(source))
	Expect(block).To(HaveLen(2), "scan-report-types.ts must declare %s", typeName)

	names := []string{}
	for _, match := range regexp.MustCompile(`(?m)^ {2}(\w+)\??:`).FindAllStringSubmatch(block[1], -1) {
		names = append(names, match[1])
	}
	Expect(names).ToNot(BeEmpty(), "%s declares no fields — has the type moved?", typeName)
	sort.Strings(names)
	return names
}

var _ = Describe("the scan report payload", func() {
	enabled := true

	full := api.ScanReport{
		Scan:         api.Scan{ID: "1", Name: "nuclei-safe-1"},
		Findings:     []api.Finding{{TemplateID: "http/tls-version"}},
		Parameters:   map[string]any{"rate-limit": float64(50)},
		GeneratedAt:  "2026-03-14T09:30:00Z",
		FindingLimit: 2000,
		SourceURL:    "http://localhost:8280/scans/1",
		Options: &api.ScanReportOptions{
			Title:               "Quarterly Review",
			Subtitle:            "Q1",
			Classification:      "Confidential",
			PreparedBy:          "Security",
			Audience:            "Platform",
			Scope:               "every production host",
			Watermark:           "DRAFT",
			MinSeverity:         api.SeverityMedium,
			MaxDetailedFindings: 25,
			Sections: &api.ScanReportSections{
				Coverage: &enabled, Traffic: &enabled, Breakdowns: &enabled,
				SummaryTable: &enabled, DetailedFindings: &enabled,
				Evidence: &enabled, Appendix: &enabled,
			},
		},
	}

	It("emits exactly the keys the template declares as its input", func() {
		Expect(keys(full)).To(Equal(templateContract("ScanReportData")))
	})

	It("emits exactly the option keys the template declares", func() {
		Expect(keys(full.Options)).To(Equal(templateContract("ReportOptions")))
	})

	It("emits exactly the section keys the template declares", func() {
		Expect(keys(full.Options.Sections)).To(Equal(templateContract("ReportSections")))
	})

	It("omits presentation the caller did not set, so the template applies its own defaults", func() {
		bare := api.ScanReport{Scan: api.Scan{ID: "1"}, GeneratedAt: "2026-03-14T09:30:00Z"}

		Expect(keys(bare)).To(Equal([]string{"findings", "generatedAt", "scan"}))
	})

	It("emits an empty findings list rather than null, which the template maps over unchecked", func() {
		encoded, err := json.Marshal(api.ScanReport{Scan: api.Scan{ID: "1"}})
		Expect(err).ToNot(HaveOccurred())
		Expect(string(encoded)).To(ContainSubstring(`"findings":[]`))
	})
})
