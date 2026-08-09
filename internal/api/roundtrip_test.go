package api_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
)

func TestAPI(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "api")
}

// repoRoot walks up from the test's working directory to the module root, so
// the fixtures resolve no matter where the test binary is run from.
func repoRoot() string {
	dir, err := os.Getwd()
	Expect(err).ToNot(HaveOccurred())
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		Expect(parent).ToNot(Equal(dir), "go.mod not found above the working directory")
		dir = parent
	}
}

// The wire type has to reproduce the TypeScript documents exactly. 207 real
// documents times ~60 optional fields is where a rewrite like this quietly goes
// wrong: Go marshals a nil slice as null where TypeScript wrote [], and a plain
// string with omitempty erases an empty value the schema explicitly allows.
// Decoding and re-encoding every checked-in document is a mechanical,
// exhaustive proof that the projection is lossless.
var _ = Describe("TargetDocument", func() {
	DescribeTable("round-trips every captured document byte-for-byte",
		func(dir string, required bool) {
			paths, err := filepath.Glob(filepath.Join(repoRoot(), dir, "*.json"))
			Expect(err).ToNot(HaveOccurred())
			if !required && len(paths) == 0 {
				Skip("no local capture in " + dir)
			}
			Expect(paths).ToNot(BeEmpty(), "no documents found in %s", dir)

			for _, path := range paths {
				original, err := os.ReadFile(path)
				Expect(err).ToNot(HaveOccurred())

				var target api.TargetDocument
				Expect(json.Unmarshal(original, &target)).To(Succeed(), "decoding %s", path)

				encoded, err := json.Marshal(target)
				Expect(err).ToNot(HaveOccurred())
				Expect(encoded).To(MatchJSON(original), "re-encoding %s", filepath.Base(path))
			}
		},
		Entry("the committed snapshot", "contract/snapshot/inventory/targets", true),
		Entry("the API responses captured from the TypeScript server", "contract/golden/subset/targets", true),
		// The full 207-host capture is gitignored — it describes live
		// infrastructure. It is the strongest version of this assertion, so run
		// it whenever the developer still has it, and skip in CI.
		Entry("the full local capture, when present", "contract/golden/full/targets", false),
	)

	// Decoding must not invent fields either: an unknown key in a document would
	// be silently dropped by encoding/json and reappear as a missing key above,
	// so the round-trip already covers it. What it cannot cover is a field the
	// schema allows but no document currently uses.
	Describe("fields absent from the live data", func() {
		It("preserves an empty string where the schema permits one", func() {
			// http.title, every tls string and cpe product/vendor have no
			// minLength, and the observation normalizer deliberately keeps "".
			const document = `{
				"$schema": "../target.schema.json", "version": 1, "host": "a.example.test",
				"class": "non-prod", "profiles": ["safe"], "tags": [],
				"http": {"title": "", "webserver": "", "content_type": ""},
				"tls": {"subject_cn": "", "cipher": ""},
				"tech": {"cpe": [{"cpe": "cpe:2.3:a", "product": "", "vendor": ""}]}
			}`

			var target api.TargetDocument
			Expect(json.Unmarshal([]byte(document), &target)).To(Succeed())
			encoded, err := json.Marshal(target)
			Expect(err).ToNot(HaveOccurred())
			Expect(encoded).To(MatchJSON(document))
		})

		It("preserves an autonomous system number of zero", func() {
			const document = `{
				"$schema": "../target.schema.json", "version": 1, "host": "a.example.test",
				"class": "non-prod", "profiles": ["safe"], "tags": [],
				"network": {"asn": {"number": 0}}
			}`

			var target api.TargetDocument
			Expect(json.Unmarshal([]byte(document), &target)).To(Succeed())
			Expect(target.Network.ASN.Number).ToNot(BeNil())
			Expect(*target.Network.ASN.Number).To(Equal(0))

			encoded, err := json.Marshal(target)
			Expect(err).ToNot(HaveOccurred())
			Expect(encoded).To(MatchJSON(document))
		})

		It("preserves a last_findings count of zero", func() {
			const document = `{
				"$schema": "../target.schema.json", "version": 1, "host": "a.example.test",
				"class": "non-prod", "profiles": ["safe"], "tags": [],
				"scan": {"last_scan": "2026-01-01T00:00:00Z", "last_findings": 0}
			}`

			var target api.TargetDocument
			Expect(json.Unmarshal([]byte(document), &target)).To(Succeed())
			encoded, err := json.Marshal(target)
			Expect(err).ToNot(HaveOccurred())
			Expect(encoded).To(MatchJSON(document))
		})

		It("emits required arrays as [] rather than null", func() {
			// A nil Go slice marshals to null, which would break the editor's
			// array controls and violate the schema's `required`.
			encoded, err := json.Marshal(api.TargetDocument{
				Schema: api.TargetSchemaRef, Version: api.TargetVersion,
				Host: "a.example.test", Class: api.ClassNonProd,
			})
			Expect(err).ToNot(HaveOccurred())
			Expect(string(encoded)).To(ContainSubstring(`"profiles":[]`))
			Expect(string(encoded)).To(ContainSubstring(`"tags":[]`))
			Expect(string(encoded)).ToNot(ContainSubstring("null"))
		})
	})
})
