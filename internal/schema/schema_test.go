package schema_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/schema"
)

func TestSchema(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "schema")
}

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

// base is a minimally valid target; each spec perturbs one thing.
func base() map[string]any {
	return map[string]any{
		"$schema":  "../target.schema.json",
		"version":  float64(1),
		"host":     "a.example.test",
		"class":    "non-prod",
		"profiles": []any{"safe"},
		"tags":     []any{},
	}
}

var _ = Describe("target schema", func() {
	It("accepts every checked-in document", func() {
		paths, err := filepath.Glob(filepath.Join(repoRoot(), "inventory/targets/*.json"))
		Expect(err).ToNot(HaveOccurred())
		Expect(paths).To(HaveLen(207))

		for _, path := range paths {
			raw, err := os.ReadFile(path)
			Expect(err).ToNot(HaveOccurred())
			Expect(schema.ValidateTargetJSON(filepath.Base(path), raw)).
				To(Succeed(), "validating %s", filepath.Base(path))
		}
	})

	It("accepts the manifest", func() {
		raw, err := os.ReadFile(filepath.Join(repoRoot(), "inventory/inventory.json"))
		Expect(err).ToNot(HaveOccurred())
		var manifest any
		Expect(json.Unmarshal(raw, &manifest)).To(Succeed())
		Expect(schema.ValidateInventory("inventory.json", manifest)).To(Succeed())
	})

	DescribeTable("accepts discovered target identities",
		func(host string) {
			document := base()
			document["host"] = host
			document["class"] = "unclassified"
			Expect(schema.ValidateTarget("t.json", document)).To(Succeed())
		},
		Entry("a DNS name", "new.example.test"),
		Entry("an IPv4 address", "192.0.2.10"),
		Entry("an IPv6 address", "2001:db8::10"),
	)

	// observed is `additionalProperties: false` and the failure kinds are an
	// enum, so the schema has to be taught every kind the prober can produce.
	// Adding one to api.Failures() and not here rejects the first target it
	// happens to.
	It("accepts every failure the prober can classify", func() {
		for _, failure := range api.Failures() {
			document := base()
			document["observed"] = map[string]any{
				"last_attempt": "2026-01-01T00:00:00Z",
				"error":        "the host did not answer",
				"failure":      string(failure),
			}
			Expect(schema.ValidateTarget("t.json", document)).
				To(Succeed(), "validating failure %q", failure)
		}
	})

	It("rejects a failure kind the prober cannot produce", func() {
		document := base()
		document["observed"] = map[string]any{"failure": "gremlins"}
		Expect(schema.ValidateTarget("t.json", document)).To(HaveOccurred())
	})

	// Profiles are rows, not a closed vocabulary: an engine ships dozens and a
	// user can create more. The schema constrains the shape of a name — the same
	// rule the profile table's check constraint enforces — and leaves existence
	// to the store, which is the only thing that can actually know.
	DescribeTable("accepts any profile name the profile table could hold",
		func(profile string) {
			document := base()
			document["profiles"] = []any{profile}
			Expect(schema.ValidateTarget("t.json", document)).To(Succeed())
		},
		Entry("a curated profile", "k8s"),
		Entry("an imported upstream profile", "subdomain-takeovers"),
		Entry("a profile someone created", "our-internal-baseline"),
	)

	// The conditional rule is the one piece of the schema a naive Go validator
	// gets wrong, and both directions are load-bearing: the UI relies on it to
	// force a reason when deactivating and to clear it when reactivating.
	Describe("the deactivated/reason rule", func() {
		It("requires a reason when the class is deactivated", func() {
			document := base()
			document["class"] = "deactivated"

			err := schema.ValidateTarget("t.json", document)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("reason"))
		})

		It("accepts a deactivated target that carries a reason", func() {
			document := base()
			document["class"] = "deactivated"
			document["reason"] = "retired 2026-01"

			Expect(schema.ValidateTarget("t.json", document)).To(Succeed())
		})

		It("forbids a reason on any other class", func() {
			document := base()
			document["reason"] = "should not be here"

			Expect(schema.ValidateTarget("t.json", document)).To(HaveOccurred())
		})
	})

	DescribeTable("rejects invalid documents",
		func(mutate func(map[string]any), expected string) {
			document := base()
			mutate(document)

			err := schema.ValidateTarget("t.json", document)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(HavePrefix("t.json: "))
			Expect(err.Error()).To(ContainSubstring(expected))
		},
		Entry("an unknown top-level field",
			func(d map[string]any) { d["nope"] = 1 }, "nope"),
		Entry("an unknown class",
			func(d map[string]any) { d["class"] = "staging" }, "value must be one of"),
		Entry("an empty profiles array",
			func(d map[string]any) { d["profiles"] = []any{} }, "minItems"),
		Entry("a profile name the profile table could not hold",
			func(d map[string]any) { d["profiles"] = []any{"Aggressive Scan"} }, "pattern"),
		Entry("a duplicated profile",
			func(d map[string]any) { d["profiles"] = []any{"safe", "safe"} }, "items at 0 and 1 are equal"),
		Entry("an uppercase host",
			func(d map[string]any) { d["host"] = "A.example.test" }, "pattern"),
		Entry("a port above the maximum",
			func(d map[string]any) { d["ports"] = []any{float64(65536)} }, "maximum"),
		Entry("a port below the minimum",
			func(d map[string]any) { d["ports"] = []any{float64(0)} }, "minimum"),
		Entry("an empty tag",
			func(d map[string]any) { d["tags"] = []any{""} }, "minLength"),
		Entry("a machine-owned field with an unknown key",
			func(d map[string]any) { d["http"] = map[string]any{"bogus": 1} }, "bogus"),
		Entry("a status code outside the HTTP range",
			func(d map[string]any) { d["http"] = map[string]any{"status_code": float64(99)} }, "minimum"),
		Entry("a malformed timestamp",
			func(d map[string]any) { d["observed"] = map[string]any{"last_seen": "yesterday"} }, "date-time"),
		Entry("a malformed address",
			func(d map[string]any) { d["network"] = map[string]any{"ipv4": []any{"999.1.1.1"}} }, "ipv4"),
	)

	It("names the document in the error so a bulk import can report which one failed", func() {
		document := base()
		document["class"] = "nonsense"

		err := schema.ValidateTarget("beta.example.test.json", document)
		Expect(err).To(MatchError(HavePrefix("beta.example.test.json: ")))
	})
})
