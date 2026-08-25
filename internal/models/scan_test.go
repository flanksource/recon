package models_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
)

func TestModels(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "models")
}

// A finding carries the raw request and response an engine saw. Anything that
// probes a binary protocol — TLS, a compressed body, a network service — sees
// NUL bytes routinely, and Postgres accepts them in neither text nor jsonb. One
// such response used to abort the batch insert for a whole scan, losing every
// finding in it and leaving the run stuck reporting "running".
var _ = Describe("storing a finding that saw binary bytes", func() {
	build := func(finding api.Finding) models.Finding {
		return models.FindingFrom("scan-1", 0, finding, "")
	}

	It("keeps a finding Postgres can store, marking where the byte was", func() {
		row := build(api.Finding{
			TemplateID: "tls-version",
			Name:       "TLS\x00Version",
			Host:       "example.test",
			MatchedAt:  "example.test:443",
			Response:   "HTTP/1.1 200 OK\r\n\r\n\x00\x01binary",
		})

		Expect(row.Name).To(Equal("TLS�Version"))
		Expect(*row.Response).To(Equal("HTTP/1.1 200 OK\r\n\r\n�\x01binary"))
	})

	It("scrubs the nested raw record, keys and values alike", func() {
		row := build(api.Finding{
			TemplateID: "tls-version",
			Raw: map[string]any{
				"response":  "body\x00",
				"extracted": []any{"a\x00b", "clean"},
				"meta":      map[string]any{"head\x00er": "value\x00"},
			},
		})

		Expect(row.Raw.Get()).To(Equal(map[string]any{
			"response":  "body�",
			"extracted": []any{"a�b", "clean"},
			"meta":      map[string]any{"head�er": "value�"},
		}))
	})

	It("scrubs every string column a finding can fill", func() {
		row := build(api.Finding{
			TemplateID:  "id\x00",
			Name:        "name\x00",
			Host:        "host\x00",
			MatchedAt:   "matched\x00",
			MatcherName: "matcher\x00",
			Type:        "type\x00",
			Tags:        []string{"tag\x00"},
			Extracted:   []string{"found\x00"},
			Remediation: "fix\x00",
			Reference:   []string{"https://example.test/\x00"},
			Curl:        "curl\x00",
			Request:     "GET /\x00",
			Response:    "200\x00",
		})

		Expect([]string{
			row.TemplateID, row.Name, row.Host, row.MatchedAt,
			*row.MatcherName, *row.Type, row.Tags[0], row.Extracted[0],
			*row.Remediation, row.Reference[0], *row.Curl, *row.Request, *row.Response,
		}).To(Equal([]string{
			"id�", "name�", "host�", "matched�",
			"matcher�", "type�", "tag�", "found�",
			"fix�", "https://example.test/�", "curl�", "GET /�", "200�",
		}))
	})

	It("leaves an ordinary finding byte-for-byte alone", func() {
		finding := api.Finding{
			TargetID:   "gcp-production",
			TemplateID: "http-missing-security-headers",
			Name:       "HTTP Missing Security Headers",
			Severity:   api.SeverityInfo,
			Host:       "example.test",
			MatchedAt:  "https://example.test",
			Tags:       []string{"misconfig", "headers"},
			Raw:        map[string]any{"matched-at": "https://example.test"},
		}

		row := build(finding)

		// A pointer, matching the nullable column and the two sibling models: an
		// unselected target is absent rather than the empty string, which is what
		// findings_target_idx would otherwise be full of.
		Expect(row.TargetID).To(HaveValue(Equal(finding.TargetID)))
		Expect(row.Document(nil).TargetID).To(Equal(finding.TargetID))
		Expect(row.Name).To(Equal(finding.Name))
		Expect([]string(row.Tags)).To(Equal(finding.Tags))
		Expect(row.Raw.Get()).To(Equal(finding.Raw))
	})

	It("keeps an absent raw record as SQL NULL rather than an empty object", func() {
		Expect(build(api.Finding{TemplateID: "tls-version"}).Raw.Get()).To(BeNil())
	})
})
