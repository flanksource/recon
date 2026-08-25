package models_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/models"
	"github.com/flanksource/recon/internal/ocsf"
)

func TestModels(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "models")
}

func build(finding api.Finding) models.Finding {
	return models.FindingFrom("scan-1", 0, finding, "")
}

// A finding carries the raw request and response an engine saw. Anything that
// probes a binary protocol — TLS, a compressed body, a network service — sees
// NUL bytes routinely, and Postgres accepts them in neither text nor jsonb. One
// such response used to abort the batch insert for a whole scan, losing every
// finding in it and leaving the run stuck reporting "running".
var _ = Describe("storing a finding that saw binary bytes", func() {
	It("scrubs every string column a finding can fill", func() {
		row := build(api.Finding{
			DetectionFinding: ocsf.DetectionFinding{
				StatusCode:   "code\x00",
				StatusDetail: "detail\x00",
			},
			CheckID:   "id\x00",
			Engine:    "engine\x00",
			Host:      "host\x00",
			MatchedAt: "matched\x00",
			TargetID:  "target\x00",
			Tags:      []string{"tag\x00"},
		})

		Expect([]string{
			row.CheckID, row.Engine, row.Host, row.MatchedAt,
			*row.TargetID, row.Tags[0], *row.StatusCode, *row.StatusDetail,
		}).To(Equal([]string{
			"id�", "engine�", "host�", "matched�",
			"target�", "tag�", "code�", "detail�",
		}))
	})

	// What used to be the `response` column is an evidence entry now, and what
	// used to be `name` is finding_info.title. Scrubbing only the columns would
	// have moved the failure rather than fixed it.
	It("scrubs the OCSF record, not only the columns beside it", func() {
		row := build(api.Finding{
			DetectionFinding: ocsf.DetectionFinding{
				FindingInfo: &ocsf.FindingInfo{Title: "TLS\x00Version", Types: []string{"tag\x00"}},
				Remediation: &ocsf.Remediation{Desc: "fix\x00"},
				Evidences: []ocsf.Evidences{{
					HTTPResponse: &ocsf.HTTPResponse{Message: "HTTP/1.1 200 OK\r\n\r\n\x00\x01binary"},
				}},
			},
			CheckID: "tls-version",
		})

		Expect(row.FindingInfo.V.Title).To(Equal("TLS�Version"))
		Expect(row.FindingInfo.V.Types).To(Equal([]string{"tag�"}))
		Expect(row.Remediation.V.Desc).To(Equal("fix�"))
		Expect((*row.Evidences.V)[0].HTTPResponse.Message).
			To(Equal("HTTP/1.1 200 OK\r\n\r\n�\x01binary"))
	})

	// unmapped is arbitrary JSON, so a NUL can be anywhere in it — including in
	// a key, which fails the jsonb cast just as a value does.
	It("scrubs the engine's own extras, keys and values alike", func() {
		row := build(api.Finding{
			DetectionFinding: ocsf.DetectionFinding{
				Unmapped: map[string]any{
					"response":  "body\x00",
					"extracted": []any{"a\x00b", "clean"},
					"meta":      map[string]any{"head\x00er": "value\x00"},
				},
			},
			CheckID: "tls-version",
		})

		Expect(row.Unmapped.Get()).To(Equal(map[string]any{
			"response":  "body�",
			"extracted": []any{"a�b", "clean"},
			"meta":      map[string]any{"head�er": "value�"},
		}))
	})

	// json_t: the payload is the engine's own shape, so it is stored as encoded
	// bytes and a NUL among them fails the same cast.
	It("scrubs a json_t evidence payload", func() {
		row := build(api.Finding{
			DetectionFinding: ocsf.DetectionFinding{
				Evidences: []ocsf.Evidences{{Data: json.RawMessage("{\"line\":\"a\x00b\"}")}},
			},
			CheckID: "trivy/secret",
		})

		Expect(string((*row.Evidences.V)[0].Data)).To(Equal(`{"line":"a�b"}`))
	})
})

var _ = Describe("projecting a finding through the database", func() {
	// The round trip that has to hold: what an adapter reports and what a reader
	// gets back are the same record. Anything the row cannot hold is a field the
	// UI renders from nothing.
	It("leaves an ordinary finding byte-for-byte alone", func() {
		finding := api.Finding{
			DetectionFinding: ocsf.DetectionFinding{
				ClassUID:    ocsf.ClassUID,
				CategoryUID: ocsf.CategoryUID,
				ActivityID:  ocsf.ActivityIDCreate,
				TypeUID:     ocsf.TypeUID(ocsf.ActivityIDCreate),
				SeverityID:  ocsf.SeverityIDInformational,
				StatusID:    ocsf.StatusIDNew,
				Time:        1786000000000,
				FindingInfo: &ocsf.FindingInfo{
					UID:   "http-missing-security-headers",
					Title: "HTTP Missing Security Headers",
					Desc:  "The response carried none of the usual headers.",
					Types: []string{"misconfig", "headers"},
				},
				Metadata: &ocsf.Metadata{
					Version:   ocsf.Version,
					EventCode: "http-missing-security-headers",
					Product:   &ocsf.Product{Name: "nuclei", VendorName: api.Vendor},
				},
				Remediation: &ocsf.Remediation{
					Desc:       "Set the headers.",
					References: []string{"https://example.test/headers"},
				},
				Evidences: []ocsf.Evidences{{
					URL:          &ocsf.URL{URLString: "https://example.test"},
					HTTPRequest:  &ocsf.HTTPRequest{Args: "GET / HTTP/1.1"},
					HTTPResponse: &ocsf.HTTPResponse{Message: "HTTP/1.1 200 OK"},
				}},
				Unmapped: map[string]any{"protocol": "http"},
			},
			TargetID:  "gcp-production",
			ScanID:    "scan-1",
			Engine:    "nuclei",
			CheckID:   "http-missing-security-headers",
			Host:      "example.test",
			MatchedAt: "https://example.test",
			Tags:      []string{"misconfig", "headers"},
			Resources: []api.ResourceRef{{
				Provider: "nuclei", Scope: "example.test", UID: "https://example.test",
			}},
		}

		row := build(finding)
		restored := row.Document(finding.Resources)
		restored.ScanID = finding.ScanID

		Expect(mustEncode(restored)).To(Equal(mustEncode(finding)))
	})

	// A pointer, matching the nullable column and the two sibling models: an
	// unselected target is absent rather than the empty string, which is what
	// findings_target_idx would otherwise be full of.
	It("keeps an unselected target absent rather than empty", func() {
		Expect(build(api.Finding{CheckID: "x"}).TargetID).To(BeNil())
		Expect(build(api.Finding{CheckID: "x", TargetID: "t"}).TargetID).
			To(HaveValue(Equal("t")))
	})

	It("keeps an absent OCSF object as SQL NULL rather than an empty one", func() {
		row := build(api.Finding{CheckID: "tls-version"})
		Expect(row.FindingInfo.V).To(BeNil())
		Expect(row.Cloud.V).To(BeNil())
		Expect(row.Unmapped.Get()).To(BeNil())
		Expect(row.Evidences.V).To(BeNil())
	})

	// Zero is 1970, not "no time". An engine that reported none must not have a
	// date invented for it.
	It("keeps an unreported time as SQL NULL rather than the epoch", func() {
		Expect(build(api.Finding{CheckID: "x"}).Time).To(BeNil())
		Expect(build(api.Finding{CheckID: "x"}).Document(nil).Time).To(BeZero())
	})
})

// The column that answers "shouldn't we be bounding this". Nothing bounded the
// record it replaced: one provider document runs to 95KB, all of it was stored,
// and all of it was shipped to Mission Control and into every report.
var _ = Describe("bounding the evidence a finding carries", func() {
	entry := func(size int) ocsf.Evidences {
		return ocsf.Evidences{HTTPResponse: &ocsf.HTTPResponse{Message: strings.Repeat("x", size)}}
	}

	It("stores an ordinary finding whole and says so", func() {
		row := build(api.Finding{CheckID: "x", DetectionFinding: ocsf.DetectionFinding{
			Evidences: []ocsf.Evidences{entry(1024)},
		}})

		Expect(*row.Evidences.V).To(HaveLen(1))
		Expect(row.EvidencesTruncated).To(BeFalse())
	})

	// Whole entries from the end, not a clipped payload: an evidence entry is an
	// object with an at_least_one constraint on it, and half of one is not a
	// smaller entry but an invalid one.
	It("drops whole entries rather than clipping one in half", func() {
		row := build(api.Finding{CheckID: "x", DetectionFinding: ocsf.DetectionFinding{
			Evidences: []ocsf.Evidences{
				entry(1024), entry(models.MaxEvidenceBytes), entry(1024),
			},
		}})

		Expect(row.EvidencesTruncated).To(BeTrue())
		Expect(len(*row.Evidences.V)).To(BeNumerically("<", 3))
		for _, kept := range *row.Evidences.V {
			Expect(kept.HTTPResponse.Message).To(HaveLen(1024),
				"a kept entry is intact, or it is not evidence of anything")
		}
	})

	It("keeps a finding whose single entry is oversized storable", func() {
		row := build(api.Finding{CheckID: "x", DetectionFinding: ocsf.DetectionFinding{
			Evidences: []ocsf.Evidences{entry(models.MaxEvidenceBytes * 2)},
		}})

		Expect(row.EvidencesTruncated).To(BeTrue())
		Expect(row.Evidences.V).To(BeNil())
	})
})

func mustEncode(finding api.Finding) string {
	encoded, err := json.Marshal(finding)
	Expect(err).ToNot(HaveOccurred())
	return string(encoded)
}
