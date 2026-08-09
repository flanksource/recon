package observe_test

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/flanksource/recon/internal/observe"
)

func record(pairs ...any) map[string]any {
	out := map[string]any{}
	for i := 0; i < len(pairs); i += 2 {
		out[pairs[i].(string)] = pairs[i+1]
	}
	return out
}

var _ = Describe("ranking a record by status", func() {
	// The whole ladder, in the order it prefers records.
	DescribeTable("assigns rank",
		func(expected int, fields map[string]any) {
			Expect(observe.StatusRank(fields)).To(Equal(expected))
		},
		Entry("0 to a 2xx", 0, record("status_code", 200.0)),
		Entry("0 to the top of the live band", 0, record("status_code", 399.0)),
		Entry("1 to an unauthorized challenge", 1, record("status_code", 401.0)),
		Entry("1 to a forbidden response", 1, record("status_code", 403.0)),
		Entry("2 to any other client error", 2, record("status_code", 400.0)),
		Entry("2 to a teapot", 2, record("status_code", 418.0)),
		Entry("3 to a server error", 3, record("status_code", 500.0)),
		Entry("4 to a not found", 4, record("status_code", 404.0)),
		Entry("4 to a gone", 4, record("status_code", 410.0)),
		Entry("5 to a record with no status at all", 5, record("url", "https://example.test")),
		Entry("5 to a status below the live band", 5, record("status_code", 100.0)),
		Entry("5 to a fractional status, which is not an integer", 5, record("status_code", 200.5)),
		Entry("6 to an outright failure, whatever its status", 6, record("failed", true, "status_code", 200.0)),
		Entry("no failure rank to a non-boolean flag", 0, record("failed", "true", "status_code", 200.0)),
	)

	It("coerces a string status the way Number() does", func() {
		Expect(observe.StatusRank(record("status_code", "401"))).To(Equal(1))
	})
})

var _ = Describe("picking the primary record", func() {
	It("returns nil when nothing responded", func() {
		Expect(observe.PrimaryRecord(nil)).To(BeNil())
	})

	It("prefers the better status rank over everything else", func() {
		primary := observe.PrimaryRecord([]map[string]any{
			record("url", "https://a.test", "status_code", 500.0, "port", 443.0, "scheme", "https"),
			record("url", "https://b.test", "status_code", 200.0, "port", 8443.0, "scheme", "http"),
		})
		Expect(primary["url"]).To(Equal("https://b.test"))
	})

	It("prefers a default port when the status ranks tie", func() {
		primary := observe.PrimaryRecord([]map[string]any{
			record("url", "https://a.test:8443", "status_code", 200.0, "port", 8443.0),
			record("url", "https://b.test", "status_code", 200.0, "port", 80.0),
		})
		Expect(primary["url"]).To(Equal("https://b.test"))
	})

	It("prefers https when the status and port ranks tie", func() {
		primary := observe.PrimaryRecord([]map[string]any{
			record("url", "http://a.test", "status_code", 200.0, "port", 80.0, "scheme", "http"),
			record("url", "https://b.test", "status_code", 200.0, "port", 443.0, "scheme", "https"),
		})
		Expect(primary["url"]).To(Equal("https://b.test"))
	})

	It("falls back to the collated url", func() {
		primary := observe.PrimaryRecord([]map[string]any{
			record("url", "https://zeta.test", "status_code", 200.0, "port", 443.0, "scheme", "https"),
			record("url", "https://alpha.test", "status_code", 200.0, "port", 443.0, "scheme", "https"),
		})
		Expect(primary["url"]).To(Equal("https://alpha.test"))
	})

	It("keeps the emitted order for records that tie on every key", func() {
		first := record("url", "https://same.test", "status_code", 200.0, "port", 443.0, "scheme", "https", "id", "first")
		second := record("url", "https://same.test", "status_code", 200.0, "port", 443.0, "scheme", "https", "id", "second")
		Expect(observe.PrimaryRecord([]map[string]any{first, second})["id"]).To(Equal("first"))
	})

	It("does not reorder the caller's slice", func() {
		records := []map[string]any{record("status_code", 500.0), record("status_code", 200.0)}
		observe.PrimaryRecord(records)
		Expect(records[0]["status_code"]).To(Equal(500.0))
	})
})

var _ = Describe("collation, the other ordering", func() {
	// discovery-profile.ts derives these with localeCompare, which compares
	// letters before case; normalize.go then re-sorts by byte on the way to disk.
	// Both orders are live at different points, and the byte one is what persists.
	It("puts Negotiate before NTLM, the opposite of byte order", func() {
		Expect(observe.UniqueCollated([]string{"NTLM", "Negotiate", "Basic"})).
			To(Equal([]string{"Basic", "Negotiate", "NTLM"}))
	})

	It("interleaves case rather than segregating it", func() {
		Expect(observe.UniqueCollated([]string{"apache", "Zope", "Apache"})).
			To(Equal([]string{"apache", "Apache", "Zope"}))
	})

	It("dedupes", func() {
		Expect(observe.UniqueCollated([]string{"SAML", "SAML"})).To(Equal([]string{"SAML"}))
	})

	It("orders letters before case", func() {
		Expect(observe.CompareCollated("a", "B")).To(BeNumerically("<", 0))
		Expect(observe.CompareCollated("B", "a")).To(BeNumerically(">", 0))
		Expect(observe.CompareCollated("a", "a")).To(Equal(0))
	})
})

var _ = Describe("reading a header", func() {
	headers := record("header", map[string]any{
		"WWW-Authenticate": "Negotiate, NTLM",
		"Set_Cookie":       []any{"a=1", "b=2", 42.0},
		"Content-Length":   9412.0,
	})

	DescribeTable("matches the name ignoring case, dashes and underscores",
		func(name string) {
			Expect(observe.HeaderValues(headers, name)).To(Equal([]string{"Negotiate, NTLM"}))
		},
		Entry("as written", "WWW-Authenticate"),
		Entry("lowercased", "www-authenticate"),
		Entry("underscored", "www_authenticate"),
		Entry("run together", "wwwauthenticate"),
		Entry("shouted", "WWWAUTHENTICATE"),
	)

	It("returns every string member of an array-valued header", func() {
		Expect(observe.HeaderValues(headers, "set-cookie")).To(Equal([]string{"a=1", "b=2"}))
	})

	It("returns nothing for a header that is neither string nor array", func() {
		Expect(observe.HeaderValues(headers, "content-length")).To(BeEmpty())
	})

	It("returns nothing for an absent header or an absent header map", func() {
		Expect(observe.HeaderValues(headers, "x-missing")).To(BeEmpty())
		Expect(observe.HeaderValues(record("url", "https://example.test"), "www-authenticate")).To(BeEmpty())
	})
})

var _ = Describe("deriving login methods", func() {
	methods := func(fields map[string]any) []string {
		out, err := observe.LoginMethods(fields)
		Expect(err).ToNot(HaveOccurred())
		return out
	}

	challenge := func(value string) map[string]any {
		return record("header", map[string]any{"WWW-Authenticate": value}, "status_code", 401.0, "path", "/")
	}

	It("reads every scheme out of a combined challenge, in ladder order", func() {
		Expect(methods(challenge("Negotiate, NTLM, Basic realm=\"x\""))).
			To(Equal([]string{"Basic", "Negotiate", "NTLM"}))
	})

	DescribeTable("recognises each scheme",
		func(header, label string) {
			Expect(methods(challenge(header))).To(ContainElement(label))
		},
		Entry("basic", "Basic realm=\"x\"", "Basic"),
		Entry("bearer", "Bearer", "Bearer"),
		Entry("digest", "Digest qop=auth", "Digest"),
		Entry("negotiate", "Negotiate", "Negotiate"),
		Entry("ntlm", "NTLM", "NTLM"),
	)

	It("requires the scheme to stand alone, not be a substring", func() {
		Expect(methods(challenge("NotBasicAtAll"))).To(BeEmpty())
	})

	It("matches the scheme case-insensitively", func() {
		Expect(methods(challenge("bAsIc realm=\"x\""))).To(Equal([]string{"Basic"}))
	})

	DescribeTable("reads the path that answered",
		func(path string, status float64, expected []string) {
			Expect(methods(record("path", path, "status_code", status))).To(Equal(expected))
		},
		Entry("a login form", "/login", 200.0, []string{"Web login"}),
		Entry("a signin form", "/signin", 200.0, []string{"Web login"}),
		Entry("an oauth2 endpoint", "/oauth2/authorize", 200.0, []string{"OAuth 2.0"}),
		Entry("a saml endpoint", "/saml/metadata", 200.0, []string{"SAML"}),
		Entry("a discovery document", "/.well-known/openid-configuration", 200.0, []string{"OpenID Connect"}),
		Entry("a redirected discovery document, which does not count", "/.well-known/openid-configuration", 302.0, nil),
		Entry("a 404, which is not evidence of anything", "/login", 404.0, nil),
		Entry("a 410, likewise", "/login", 410.0, nil),
		Entry("a deeper login path, which only the exact path matches", "/app/login", 200.0, nil),
	)

	It("gives the path leading slash when the record omits it", func() {
		Expect(methods(record("path", "login", "status_code", 200.0))).To(Equal([]string{"Web login"}))
	})

	It("ignores the path of a failed record", func() {
		Expect(methods(record("path", "/login", "status_code", 200.0, "failed", true))).To(BeEmpty())
	})

	It("falls back to the url path when there is no path field", func() {
		Expect(methods(record("url", "https://example.test/oauth2/authorize", "status_code", 200.0))).
			To(Equal([]string{"OAuth 2.0"}))
	})

	DescribeTable("reads the redirect target",
		func(location string, expected []string) {
			Expect(methods(record("location", location))).To(Equal(expected))
		},
		Entry("an oauth redirect", "https://idp.test/oauth/authorize", []string{"OAuth 2.0"}),
		Entry("an oidc redirect", "https://idp.test/oidc/auth", []string{"OpenID Connect"}),
		Entry("an openid redirect", "https://idp.test/openid/auth", []string{"OpenID Connect"}),
		Entry("a saml redirect", "https://idp.test/saml/sso", []string{"SAML"}),
		Entry("a login redirect", "/login?next=/", []string{"Web login"}),
		Entry("a signin redirect at the end of the path", "/account/signin", []string{"Web login"}),
		Entry("a path that merely contains login", "/logins", nil),
		Entry("an empty location", "", nil),
	)

	It("reports duplicates and derivation order, leaving deduplication to the caller", func() {
		derived := methods(record(
			"header", map[string]any{"WWW-Authenticate": "Negotiate, NTLM"},
			"path", "/oauth2/authorize", "status_code", 200.0, "location", "https://idp.test/oauth/x",
		))
		Expect(derived).To(Equal([]string{"Negotiate", "NTLM", "OAuth 2.0", "OAuth 2.0"}))
		Expect(observe.UniqueCollated(derived)).To(Equal([]string{"Negotiate", "NTLM", "OAuth 2.0"}))
	})

	It("fails loudly on a url it cannot parse", func() {
		_, err := observe.LoginMethods(record("url", "https://exa mple.test/\x7f", "status_code", 200.0))
		Expect(err).To(MatchError(ContainSubstring("is not a URL")))
	})
})

var _ = Describe("the path a record answered on", func() {
	path := func(fields map[string]any) string {
		out, err := observe.RecordPath(fields)
		Expect(err).ToNot(HaveOccurred())
		return out
	}

	It("prefers the explicit field", func() {
		Expect(path(record("path", "/explicit", "url", "https://example.test/from-url"))).To(Equal("/explicit"))
	})

	It("reads the url when there is no path field", func() {
		Expect(path(record("url", "https://example.test/from-url"))).To(Equal("/from-url"))
	})

	It("treats a url with no path as the root", func() {
		Expect(path(record("url", "https://example.test"))).To(Equal("/"))
	})

	It("is empty when the record carries neither", func() {
		Expect(path(record("status_code", 200.0))).To(BeEmpty())
	})

	It("is empty for a record that found nothing there", func() {
		for _, fields := range []map[string]any{
			record("path", "/gone", "status_code", 404.0),
			record("path", "/gone", "status_code", 410.0),
			record("path", "/gone"),
			record("path", "/gone", "status_code", 200.0, "failed", true),
		} {
			known, err := observe.KnownPath(fields)
			Expect(err).ToNot(HaveOccurred())
			Expect(known).To(BeEmpty(), fmt.Sprintf("%v", fields))
		}
	})
})

var _ = Describe("projecting a record for storage", func() {
	full := record(
		"url", "https://example.test",
		"header", map[string]any{"Server": "nginx"},
		"raw_header", "HTTP/1.1 200 OK\r\n",
		"request", "GET / HTTP/1.1",
		"response", "<html>",
	)

	It("strips the bulky unstructured keys and keeps the rest", func() {
		Expect(observe.InventoryProjection(full)).To(Equal(map[string]any{"url": "https://example.test"}))
	})

	It("leaves the input record alone", func() {
		observe.InventoryProjection(full)
		Expect(full).To(HaveKey("raw_header"))
	})
})
