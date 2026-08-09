package observe_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/api"
	"github.com/flanksource/recon/internal/observe"
)

func TestObserve(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "observe")
}

// capturedCases is the number of cases in the captured reference. Asserting it stops a
// truncated or partially-loaded fixture file from silently reducing coverage to
// whatever still parses.
const capturedCases = 81

// fixture is one case captured from the running TypeScript server: the document
// before the observation, the engine record, and the document the TypeScript
// produced.
type fixture struct {
	Name      string             `json:"name"`
	Target    api.TargetDocument `json:"target"`
	Record    map[string]any     `json:"record"`
	Timestamp string             `json:"timestamp"`
	Expected  json.RawMessage    `json:"expected"`
}

// repoRoot walks up to the directory holding go.mod so the fixture path does not
// depend on where the test binary was invoked from.
func repoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("repo root not found")
		}
		dir = parent
	}
}

// loadFixtures runs at tree-construction time so each case becomes its own spec,
// which is why it panics rather than using Expect.
func loadFixtures() []fixture {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "contract/fixtures/observations.json"))
	if err != nil {
		panic(err)
	}
	var fixtures []fixture
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		panic(err)
	}
	return fixtures
}

// wire renders a document the way the API would and reads it back as plain JSON,
// so comparisons are about content rather than Go types or key order.
func wire(document api.TargetDocument) map[string]any {
	encoded, err := json.Marshal(document)
	Expect(err).ToNot(HaveOccurred())
	var decoded map[string]any
	Expect(json.Unmarshal(encoded, &decoded)).To(Succeed())
	return decoded
}

func decoded(raw json.RawMessage) map[string]any {
	var out map[string]any
	Expect(json.Unmarshal(raw, &out)).To(Succeed())
	return out
}

// apply is the common path under test: a fresh target, one record, one timestamp.
func apply(host string, record map[string]any) api.TargetDocument {
	target := api.TargetDocument{Host: host, Class: api.ClassNonProd, Profiles: []string{"safe"}, Tags: []string{}}
	result, err := observe.Apply(target, record, "2026-08-09T00:00:00.000Z")
	Expect(err).ToNot(HaveOccurred())
	return result
}

var _ = Describe("replaying the captured observations", func() {
	fixtures := loadFixtures()

	It("loads every captured case", func() {
		Expect(fixtures).To(HaveLen(capturedCases))
	})

	for _, captured := range fixtures {
		captured := captured
		It("reproduces "+captured.Name, func() {
			result, err := observe.Apply(captured.Target, captured.Record, captured.Timestamp)
			Expect(err).ToNot(HaveOccurred())
			Expect(wire(result)).To(Equal(decoded(captured.Expected)))
		})
	}

	It("is idempotent: re-applying the same record changes nothing", func() {
		for _, captured := range fixtures {
			once, err := observe.Apply(captured.Target, captured.Record, captured.Timestamp)
			Expect(err).ToNot(HaveOccurred())
			twice, err := observe.Apply(once, captured.Record, captured.Timestamp)
			Expect(err).ToNot(HaveOccurred())
			Expect(wire(twice)).To(Equal(wire(once)), captured.Name)
		}
	})
})

var _ = Describe("a record that reports failure", func() {
	// Over half of the real inventory sits in this state, so the sections a
	// failure leaves alone matter more than the ones it writes.
	snapshot := api.TargetDocument{
		Host:     "example.test",
		Class:    api.ClassProd,
		Profiles: []string{"safe"},
		Tags:     []string{},
		Observed: &api.Observed{
			FirstObserved: "2026-01-15T09:30:00.000Z",
			LastSeen:      "2026-01-15T09:30:00.000Z",
			LastAttempt:   "2026-01-15T09:30:00.000Z",
		},
		Network: &api.Network{IP: "10.0.0.1"},
		HTTP:    &api.HTTP{URL: "https://example.test", StatusCode: 200},
		Tech:    &api.Tech{Names: []string{"nginx"}},
		TLS:     &api.TLS{Cipher: ptr("TLS_AES_128_GCM_SHA256")},
		Scan:    &api.ScanState{LastScan: "2026-01-15T09:30:00.000Z"},
	}

	failed := func(record map[string]any) api.TargetDocument {
		result, err := observe.Apply(snapshot, record, "2026-08-09T00:00:00.000Z")
		Expect(err).ToNot(HaveOccurred())
		return result
	}

	It("writes only last_attempt and error, preserving every other section", func() {
		result := failed(map[string]any{"input": "example.test", "failed": true, "error": "dial timeout"})
		Expect(result.Observed).To(Equal(&api.Observed{
			FirstObserved: "2026-01-15T09:30:00.000Z",
			LastSeen:      "2026-01-15T09:30:00.000Z",
			LastAttempt:   "2026-08-09T00:00:00.000Z",
			Error:         "dial timeout",
		}))
		Expect(result.Network).To(Equal(snapshot.Network))
		Expect(result.HTTP).To(Equal(snapshot.HTTP))
		Expect(result.Tech).To(Equal(snapshot.Tech))
		Expect(result.TLS).To(Equal(snapshot.TLS))
		Expect(result.Scan).To(Equal(snapshot.Scan))
	})

	It("substitutes the httpx wording when the record gives no error", func() {
		Expect(failed(map[string]any{"input": "example.test", "failed": true}).Observed.Error).
			To(Equal(observe.FailedProbeError))
	})

	It("only short-circuits on a literal true", func() {
		for _, notFailed := range []any{false, "true", 1.0, nil} {
			result := failed(map[string]any{"input": "example.test", "failed": notFailed})
			Expect(result.Observed.Error).To(BeEmpty(), fmt.Sprintf("failed=%v", notFailed))
			Expect(result.Observed.LastSeen).To(Equal("2026-08-09T00:00:00.000Z"))
		}
	})

	It("clears a stale error once the probe succeeds again", func() {
		stale := failed(map[string]any{"input": "example.test", "failed": true})
		revived, err := observe.Apply(stale, map[string]any{"input": "example.test"}, "2026-08-10T00:00:00.000Z")
		Expect(err).ToNot(HaveOccurred())
		Expect(revived.Observed).To(Equal(&api.Observed{
			FirstObserved: "2026-01-15T09:30:00.000Z",
			LastSeen:      "2026-08-10T00:00:00.000Z",
			LastAttempt:   "2026-08-10T00:00:00.000Z",
		}))
	})
})

var _ = Describe("CPE normalization", func() {
	cpes := func(entries ...any) []api.CPE {
		tech := apply("example.test", map[string]any{"input": "example.test", "cpe": entries}).Tech
		if tech == nil {
			return nil
		}
		return tech.CPE
	}

	It("splits a bare CPE positionally, mis-reading the 4-segment form", func() {
		Expect(cpes("cpe:/a:apache:httpd")).To(Equal([]api.CPE{{CPE: "cpe:/a:apache:httpd", Vendor: ptr("httpd")}}))
	})

	It("reads vendor and product correctly from the 2.3 form", func() {
		Expect(cpes("cpe:2.3:a:nginx:nginx:1.25.3")).To(Equal([]api.CPE{
			{CPE: "cpe:2.3:a:nginx:nginx:1.25.3", Vendor: ptr("nginx"), Product: ptr("nginx")},
		}))
	})

	It("keeps an empty segment as an empty string rather than dropping it", func() {
		Expect(cpes("cpe:2.3:a::product:1")).To(Equal([]api.CPE{
			{CPE: "cpe:2.3:a::product:1", Vendor: ptr(""), Product: ptr("product")},
		}))
	})

	It("takes vendor and product verbatim from the object form", func() {
		Expect(cpes(map[string]any{"cpe": "cpe:obj", "vendor": "V", "product": "P"})).To(Equal([]api.CPE{
			{CPE: "cpe:obj", Vendor: ptr("V"), Product: ptr("P")},
		}))
	})

	It("drops an object with no cpe key and any non-object, non-string entry", func() {
		Expect(cpes(map[string]any{"vendor": "orphan"}, 42.0, nil)).To(BeNil())
	})
})

var _ = Describe("string handling", func() {
	It("preserves an empty string in the five fields that bypass the guard", func() {
		result := apply("example.test", map[string]any{
			"input": "example.test", "title": "", "webserver": "", "content_type": "",
			"location": "", "time": "",
		})
		Expect(result.HTTP).To(Equal(&api.HTTP{
			Title: ptr(""), Webserver: ptr(""), ContentType: ptr(""), Location: ptr(""), ResponseTime: ptr(""),
		}))
	})

	It("drops an empty string everywhere else", func() {
		result := apply("example.test", map[string]any{
			"input": "example.test", "url": "", "scheme": "", "host_ip": "", "cdn_name": "",
			"tls": map[string]any{"cipher": ""},
		})
		Expect(result.HTTP).To(BeNil())
		Expect(result.Network).To(BeNil())
		Expect(result.TLS).To(BeNil())
	})
})

var _ = Describe("sections that collapse to absent", func() {
	It("drops a tls object whose every field is unusable", func() {
		Expect(apply("example.test", map[string]any{
			"input": "example.test",
			"tls":   map[string]any{"cipher": "", "expired": "no", "subject_org": "acme"},
		}).TLS).To(BeNil())
	})

	It("drops an asn object whose every field is unusable, and the network with it", func() {
		Expect(apply("example.test", map[string]any{
			"input": "example.test",
			"asn":   map[string]any{"as_number": "ASXYZ", "as_name": ""},
		}).Network).To(BeNil())
	})

	It("keeps a tls section for a single false boolean", func() {
		Expect(apply("example.test", map[string]any{
			"input": "example.test", "tls": map[string]any{"expired": false},
		}).TLS).To(Equal(&api.TLS{Expired: ptr(false)}))
	})

	It("keeps a cdn section that is only a name, defaulting enabled to false", func() {
		Expect(apply("example.test", map[string]any{
			"input": "example.test", "cdn_name": "cloudflare",
		}).Network.CDN).To(Equal(&api.CDN{Enabled: false, Name: "cloudflare"}))
	})
})

var _ = Describe("ASN normalization", func() {
	asn := func(fields map[string]any) *api.ASN {
		result := apply("example.test", map[string]any{"input": "example.test", "asn": fields})
		if result.Network == nil {
			return nil
		}
		return result.Network.ASN
	}

	It("strips the AS prefix in either case", func() {
		Expect(asn(map[string]any{"as_number": "AS15169"}).Number).To(Equal(ptr(15169)))
		Expect(asn(map[string]any{"as_number": "as15169"}).Number).To(Equal(ptr(15169)))
	})

	It("falls back to the legacy keys", func() {
		Expect(asn(map[string]any{"number": 64512.0, "name": "Legacy", "country": "DE", "range": "10.0.0.0/8"})).
			To(Equal(&api.ASN{Number: ptr(64512), Name: "Legacy", Country: "DE", Range: "10.0.0.0/8"}))
	})

	It("prefers the as_ keys over the legacy ones", func() {
		Expect(asn(map[string]any{"as_name": "New", "name": "Old"}).Name).To(Equal("New"))
	})

	It("drops an unparseable number without falling back to the legacy key", func() {
		Expect(asn(map[string]any{"as_number": "ASXYZ", "number": 64512.0, "as_name": "Broken"})).
			To(Equal(&api.ASN{Name: "Broken"}))
	})

	It("falls back when the prefix is all there was, because the remainder is falsy", func() {
		Expect(asn(map[string]any{"as_number": "AS", "number": 64512.0}).Number).To(Equal(ptr(64512)))
	})
})

var _ = Describe("fingerprint_hash", func() {
	hash := func(value any) *string {
		return apply("example.test", map[string]any{
			"input": "example.test", "tls": map[string]any{"fingerprint_hash": value},
		}).TLS.FingerprintHash
	}

	It("accepts a plain digest string", func() {
		Expect(hash("abc123")).To(Equal(ptr("abc123")))
	})

	It("reads sha256 out of the object form and ignores the weaker digests", func() {
		Expect(hash(map[string]any{"md5": "m", "sha1": "s", "sha256": "def456"})).To(Equal(ptr("def456")))
	})

	It("drops an object carrying no sha256", func() {
		Expect(apply("example.test", map[string]any{
			"input": "example.test", "tls": map[string]any{"fingerprint_hash": map[string]any{"md5": "m"}},
		}).TLS).To(BeNil())
	})
})

var _ = Describe("port handling", func() {
	It("keeps only whole numbers inside 1-65535, deduped and sorted", func() {
		result := apply("example.test", map[string]any{
			"input":      "example.test",
			"open_ports": []any{0.0, 65536.0, -1.0, 8443.0, 443.0, 443.0, 80.0, "22", 1.5, nil},
		})
		Expect(result.Network.OpenPorts).To(Equal([]int{22, 80, 443, 8443}))
	})

	It("keeps the boundary ports", func() {
		Expect(apply("example.test", map[string]any{
			"input": "example.test", "open_ports": []any{65535.0, 1.0},
		}).Network.OpenPorts).To(Equal([]int{1, 65535}))
	})

	It("coerces a string port and truncates a fractional status code", func() {
		result := apply("example.test", map[string]any{"input": "example.test", "port": "8443", "status_code": 200.9})
		Expect(result.HTTP.Port).To(Equal(8443))
		Expect(result.HTTP.StatusCode).To(Equal(200))
	})
})

var _ = Describe("array sorting on the way to storage", func() {
	// normalize.go re-sorts with Array.prototype.sort, which is code-unit order,
	// and it is the last sort before the document is written. See select_test.go
	// for the collated order discovery derived these in.
	It("orders login methods by byte, putting NTLM before Negotiate", func() {
		Expect(apply("example.test", map[string]any{
			"input": "example.test", "login_methods": []any{"Negotiate", "NTLM", "Basic", "NTLM"},
		}).HTTP.LoginMethods).To(Equal([]string{"Basic", "NTLM", "Negotiate"}))
	})

	It("puts every uppercase letter before every lowercase one", func() {
		Expect(apply("example.test", map[string]any{
			"input": "example.test", "tech": []any{"apache", "Zope", "Apache"},
		}).Tech.Names).To(Equal([]string{"Apache", "Zope", "apache"}))
	})

	It("dedupes addresses and sorts them", func() {
		result := apply("example.test", map[string]any{
			"input": "example.test",
			"a":     []any{"10.0.0.2", "10.0.0.1", "10.0.0.1"},
			"cname": []any{"b.test", "a.test"},
		})
		Expect(result.Network.IPv4).To(Equal([]string{"10.0.0.1", "10.0.0.2"}))
		Expect(result.Network.CNAME).To(Equal([]string{"a.test", "b.test"}))
	})
})

var _ = Describe("resolving the observed host", func() {
	It("lowercases the input field", func() {
		Expect(observe.ObservationHost(map[string]any{"input": "UPPER.example.test"})).To(Equal("upper.example.test"))
	})

	It("falls back to the URL host, without the port or path", func() {
		Expect(observe.ObservationHost(map[string]any{"url": "https://UPPER.example.test:8443/path"})).
			To(Equal("upper.example.test"))
	})

	It("rejects a record carrying neither", func() {
		_, err := observe.ObservationHost(map[string]any{"port": 443.0})
		Expect(err).To(MatchError(ContainSubstring("input or url")))
	})

	It("rejects a url with no host", func() {
		_, err := observe.ObservationHost(map[string]any{"url": "not-a-url"})
		Expect(err).To(MatchError(ContainSubstring("no host")))
	})
})

var _ = Describe("Apply input validation", func() {
	target := api.TargetDocument{Host: "example.test"}

	It("rejects a nil record", func() {
		_, err := observe.Apply(target, nil, "2026-08-09T00:00:00.000Z")
		Expect(err).To(MatchError(ContainSubstring("must be an object")))
	})

	It("rejects an empty timestamp", func() {
		_, err := observe.Apply(target, map[string]any{"input": "example.test"}, "")
		Expect(err).To(MatchError(ContainSubstring("timestamp is required")))
	})

	It("rejects a record for a different host", func() {
		_, err := observe.Apply(target, map[string]any{"input": "other.test"}, "2026-08-09T00:00:00.000Z")
		Expect(err).To(MatchError(ContainSubstring("does not match")))
	})

	It("leaves the curated fields untouched", func() {
		curated := api.TargetDocument{
			Host: "example.test", Class: api.ClassProd, App: "billing", Cluster: "eu-01",
			Profiles: []string{"safe", "intrusive"}, Ports: []int{8080}, Tags: []string{"pci"}, Notes: "keep me",
		}
		result, err := observe.Apply(curated, map[string]any{"input": "example.test"}, "2026-08-09T00:00:00.000Z")
		Expect(err).ToNot(HaveOccurred())
		Expect(result.Curated()).To(Equal(curated.Curated()))
	})
})

func ptr[T any](value T) *T { return &value }
