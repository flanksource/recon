package observe

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

// StrippedKeys are the record keys discovery drops before an observation is
// stored. They are the bulky, unstructured halves of the probe — raw bytes and
// header maps — and nothing downstream reads them.
var StrippedKeys = []string{"header", "raw_header", "request", "response"}

// InventoryProjection copies a record without the stripped keys. The input is
// left untouched.
func InventoryProjection(record map[string]any) map[string]any {
	projection := make(map[string]any, len(record))
	for key, value := range record {
		projection[key] = value
	}
	for _, key := range StrippedKeys {
		delete(projection, key)
	}
	return projection
}

// StatusRank ranks a record by how much the status code suggests a real
// endpoint. Lower is better, and the ladder is exhaustive over 0–6: a live
// response, then an auth challenge, then any other client error, then a server
// error, then gone, then no status at all, then an outright failure. It is
// ordered by usefulness rather than by numeric status, which is why 401 outranks
// a 2xx-adjacent 3xx-free 4xx and why 5xx beats 404.
func StatusRank(record map[string]any) int {
	if isTrue(record["failed"]) {
		return 6
	}
	status, ok := jsInteger(record, "status_code")
	if !ok {
		return 5
	}
	switch {
	case status >= 200 && status < 400:
		return 0
	case status == 401 || status == 403:
		return 1
	case status >= 400 && status < 500 && status != 404 && status != 410:
		return 2
	case status >= 500:
		return 3
	case status == 404 || status == 410:
		return 4
	}
	return 5
}

// PrimaryRecord picks the record that best represents a host when several
// probes answered for it. Ties fall through status rank, then a preference for
// the default ports, then for https, then to the URL under locale collation.
// Returns nil for an empty input, which is the caller's signal that nothing
// responded.
func PrimaryRecord(records []map[string]any) map[string]any {
	if len(records) == 0 {
		return nil
	}
	ordered := append([]map[string]any(nil), records...)
	collator := collate.New(language.Und)
	// Stable, because Array.prototype.sort is: two records that tie on every key
	// keep the order the probes emitted them in.
	sort.SliceStable(ordered, func(left, right int) bool {
		return compareRecords(collator, ordered[left], ordered[right]) < 0
	})
	return ordered[0]
}

func compareRecords(collator *collate.Collator, left, right map[string]any) int {
	if rank := StatusRank(left) - StatusRank(right); rank != 0 {
		return rank
	}
	if rank := defaultPortRank(left) - defaultPortRank(right); rank != 0 {
		return rank
	}
	if rank := schemeRank(left) - schemeRank(right); rank != 0 {
		return rank
	}
	return collator.CompareString(jsStringOr(left["url"], ""), jsStringOr(right["url"], ""))
}

func defaultPortRank(record map[string]any) int {
	port, _ := jsInteger(record, "port")
	if port == 80 || port == 443 {
		return 0
	}
	return 1
}

func schemeRank(record map[string]any) int {
	if jsStringOr(record["scheme"], "") == "https" {
		return 0
	}
	return 1
}

// CompareCollated stands in for JavaScript's String.prototype.localeCompare,
// which is what discovery-profile.ts sorts derived values with. It is not byte
// order: "Negotiate" sorts before "NTLM" here because collation compares letters
// before case, while jsStrings in normalize.go puts "NTLM" first. Both are
// correct for their step — normalize.go runs last, so byte order is what the
// inventory ends up holding.
func CompareCollated(left, right string) int {
	collator := collators.Get().(*collate.Collator)
	defer collators.Put(collator)
	return collator.CompareString(left, right)
}

// UniqueCollated dedupes by first occurrence and sorts under collation, the way
// uniqueSorted(..., localeCompare) does.
func UniqueCollated(values []string) []string {
	seen := make(map[string]bool, len(values))
	var out []string
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	collator := collate.New(language.Und)
	sort.SliceStable(out, func(left, right int) bool {
		return collator.CompareString(out[left], out[right]) < 0
	})
	return out
}

// collate.Collator keeps a scratch buffer and is not safe for concurrent use.
var collators = sync.Pool{New: func() any { return collate.New(language.Und) }}

// HeaderValues looks a header up ignoring case, dashes and underscores, and
// normalizes the string-or-array shape httpx emits into a slice.
//
// The original took the first matching entry in insertion order. Go map order is
// randomized, so when two keys normalize to the same name the lexicographically
// first is taken instead — deterministic, and unreachable with real probe output.
func HeaderValues(record map[string]any, name string) []string {
	headers := jsObject(record["header"])
	if headers == nil {
		return nil
	}
	wanted := headerKey(name)
	var matches []string
	for key := range headers {
		if headerKey(key) == wanted {
			matches = append(matches, key)
		}
	}
	if len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)

	switch value := headers[matches[0]].(type) {
	case string:
		return []string{value}
	case []any:
		var out []string
		for _, item := range value {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}

func headerKey(name string) string {
	return strings.NewReplacer("-", "", "_", "").Replace(strings.ToLower(name))
}

// authSchemes maps the WWW-Authenticate challenge token to the label stored on
// the target, in the order they are appended.
var authSchemes = []struct{ token, label string }{
	{"basic", "Basic"},
	{"bearer", "Bearer"},
	{"digest", "Digest"},
	{"negotiate", "Negotiate"},
	{"ntlm", "NTLM"},
}

var (
	challengePatterns = buildChallengePatterns()
	openIDPattern     = regexp.MustCompile(`openid|oidc`)
	loginPathPattern  = regexp.MustCompile(`/(?:login|signin)(?:[/?#]|$)`)
)

func buildChallengePatterns() []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, len(authSchemes))
	for i, scheme := range authSchemes {
		patterns[i] = regexp.MustCompile(`(?i)(?:^|[\s,])` + scheme.token + `(?:[\s,]|$)`)
	}
	return patterns
}

// LoginMethods derives how a host asks a caller to authenticate, from the
// WWW-Authenticate challenge, the path that answered, and any redirect target.
// The result keeps duplicates and derivation order; UniqueCollated is what the
// caller applies before storing.
func LoginMethods(record map[string]any) ([]string, error) {
	var methods []string
	challenges := strings.Join(HeaderValues(record, "www-authenticate"), ",")
	for i, scheme := range authSchemes {
		if challengePatterns[i].MatchString(challenges) {
			methods = append(methods, scheme.label)
		}
	}

	path, err := RecordPath(record)
	if err != nil {
		return nil, err
	}
	known, err := KnownPath(record)
	if err != nil {
		return nil, err
	}
	status, hasStatus := jsInteger(record, "status_code")
	if path != "" && known != "" {
		path = strings.ToLower(path)
		if path == "/login" || path == "/signin" {
			methods = append(methods, "Web login")
		}
		if strings.Contains(path, "oauth2") {
			methods = append(methods, "OAuth 2.0")
		}
		// Only a 200 discovery document counts; a redirect to one does not.
		if strings.Contains(path, "openid-configuration") && hasStatus && status == 200 {
			methods = append(methods, "OpenID Connect")
		}
		if strings.Contains(path, "saml") {
			methods = append(methods, "SAML")
		}
	}

	location := strings.ToLower(jsStringOr(record["location"], ""))
	if location == "" {
		return methods, nil
	}
	if strings.Contains(location, "oauth") {
		methods = append(methods, "OAuth 2.0")
	}
	if openIDPattern.MatchString(location) {
		methods = append(methods, "OpenID Connect")
	}
	if strings.Contains(location, "saml") {
		methods = append(methods, "SAML")
	}
	if loginPathPattern.MatchString(location) {
		methods = append(methods, "Web login")
	}
	return methods, nil
}

// RecordPath is the path a record answered on: the explicit field if there is
// one, given a leading slash, otherwise the URL's path. It is "" only when the
// record carries neither.
func RecordPath(record map[string]any) (string, error) {
	if path, ok := jsString(record["path"]); ok {
		if strings.HasPrefix(path, "/") {
			return path, nil
		}
		return "/" + path, nil
	}
	raw, ok := jsString(record["url"])
	if !ok {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("record url %q is not a URL: %w", raw, err)
	}
	if parsed.EscapedPath() == "" {
		return "/", nil
	}
	return parsed.EscapedPath(), nil
}

// KnownPath is RecordPath, but only for a record that actually found something
// there. A failure, a missing status, a 404 or a 410 all mean the path is not
// evidence of anything and yield "".
func KnownPath(record map[string]any) (string, error) {
	status, ok := jsInteger(record, "status_code")
	if isTrue(record["failed"]) || !ok || status == 404 || status == 410 {
		return "", nil
	}
	return RecordPath(record)
}
