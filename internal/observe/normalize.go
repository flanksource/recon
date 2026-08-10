// Package observe turns a discovery engine's raw record into the machine-owned
// sections of a target document. It is a straight port of the TypeScript
// backend's inventory-observation.ts and the record-selection half of
// discovery-profile.ts, and it is deliberately faithful rather than tidy: the
// 207 documents already on disk were written by that code, so a "correction"
// here shows up as inventory churn on the next observation. The package is pure
// — values in, values out.
package observe

import (
	"fmt"
	"math"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/flanksource/recon/internal/api"
)

// FailedProbeError is the error text stored when a record reports failure
// without saying why. It is httpx's wording and is load-bearing: it is already
// persisted across the inventory.
const FailedProbeError = "httpx probe failed"

// EndpointObservation is the addressing reported by a successful port probe.
type EndpointObservation struct {
	Host  string
	IP    string
	Ports []int
}

// ObservationHost derives the host a record is about. `input` wins because it is
// what the probe was asked to look at; the URL is only consulted as a fallback.
func ObservationHost(record map[string]any) (string, error) {
	if record == nil {
		return "", fmt.Errorf("observation must be an object")
	}
	if input, ok := jsString(record["input"]); ok {
		return strings.ToLower(input), nil
	}
	raw, ok := jsString(record["url"])
	if !ok {
		return "", fmt.Errorf("observation must contain input or url")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("observation url %q is not a URL: %w", raw, err)
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("observation url %q has no host", raw)
	}
	return strings.ToLower(host), nil
}

// Apply folds one record into a target, replacing every machine-owned section
// and leaving the curated fields and the scan state alone.
func Apply(target api.TargetDocument, record map[string]any, timestamp string) (api.TargetDocument, error) {
	if record == nil {
		return api.TargetDocument{}, fmt.Errorf("observation must be an object")
	}
	if timestamp == "" {
		return api.TargetDocument{}, fmt.Errorf("observation timestamp is required")
	}
	host, err := ObservationHost(record)
	if err != nil {
		return api.TargetDocument{}, err
	}
	if host != target.Host {
		return api.TargetDocument{}, fmt.Errorf("observation host %s does not match %s", host, target.Host)
	}

	if isTrue(record["failed"]) {
		// A failed probe writes liveness only. network/http/tech/tls keep the last
		// successful snapshot rather than being cleared — most of the inventory
		// sits in exactly this state, and clearing here would erase all of it.
		observed := api.Observed{}
		if target.Observed != nil {
			observed = *target.Observed
		}
		observed.LastAttempt = timestamp
		observed.Error = jsStringOr(record["error"], FailedProbeError)
		target.Observed = &observed
		return target, nil
	}

	firstObserved := timestamp
	if target.Observed != nil {
		if seen, ok := jsString(target.Observed.FirstObserved); ok {
			firstObserved = seen
		}
	}
	// The success path builds a fresh Observed, which is what clears a stale
	// error left behind by an earlier failure.
	target.Observed = &api.Observed{FirstObserved: firstObserved, LastSeen: timestamp, LastAttempt: timestamp}
	target.Network = normalizeNetwork(record)
	target.HTTP = normalizeHTTP(record)
	target.Tech = present(api.Tech{Names: jsStrings(record["tech"]), CPE: normalizeCPE(record["cpe"])})
	target.TLS = normalizeTLS(record["tls"])
	return target, nil
}

// ApplyEndpoints updates network liveness without clearing HTTP, TLS or
// technology details collected by richer probes.
func ApplyEndpoints(target api.TargetDocument, observation EndpointObservation, timestamp string) (api.TargetDocument, error) {
	if timestamp == "" {
		return api.TargetDocument{}, fmt.Errorf("endpoint observation timestamp is required")
	}
	if observation.Host != target.Host {
		return api.TargetDocument{}, fmt.Errorf("endpoint host %s does not match %s", observation.Host, target.Host)
	}

	network := api.Network{}
	if target.Network != nil {
		network = *target.Network
	}
	if observation.IP != "" {
		network.IP = observation.IP
	}
	ports, err := normalizedPorts(observation.Ports)
	if err != nil {
		return api.TargetDocument{}, err
	}
	network.OpenPorts = ports
	target.Network = present(network)

	firstObserved := timestamp
	if target.Observed != nil && target.Observed.FirstObserved != "" {
		firstObserved = target.Observed.FirstObserved
	}
	target.Observed = &api.Observed{
		FirstObserved: firstObserved,
		LastSeen:      timestamp,
		LastAttempt:   timestamp,
	}
	return target, nil
}

func normalizedPorts(values []int) ([]int, error) {
	seen := make(map[int]struct{}, len(values))
	for _, value := range values {
		if value < 1 || value > 65535 {
			return nil, fmt.Errorf("endpoint port %d is outside 1-65535", value)
		}
		seen[value] = struct{}{}
	}
	ports := make([]int, 0, len(seen))
	for value := range seen {
		ports = append(ports, value)
	}
	sort.Ints(ports)
	return ports, nil
}

func normalizeNetwork(record map[string]any) *api.Network {
	return present(api.Network{
		IP:        jsStringOr(record["host_ip"], ""),
		IPv4:      jsStrings(record["a"]),
		IPv6:      jsStrings(record["aaaa"]),
		CNAME:     jsStrings(record["cname"]),
		Resolvers: jsStrings(record["resolvers"]),
		OpenPorts: jsPorts(record["open_ports"]),
		CDN:       normalizeCDN(record),
		ASN:       normalizeASN(jsObject(record["asn"])),
	})
}

func normalizeCDN(record map[string]any) *api.CDN {
	name := jsStringOr(record["cdn_name"], "")
	kind := jsStringOr(record["cdn_type"], "")
	enabled := jsBoolPtr(record["cdn"])
	if enabled == nil && name == "" && kind == "" {
		return nil
	}
	// A name or type on its own still means an edge was seen, and the schema makes
	// `enabled` required, so it defaults to false rather than collapsing the section.
	return &api.CDN{Enabled: enabled != nil && *enabled, Name: name, Type: kind}
}

func normalizeASN(asn map[string]any) *api.ASN {
	if asn == nil {
		return nil
	}
	return present(api.ASN{
		Number:  asnNumber(asn),
		Name:    jsStringOr(asn["as_name"], jsStringOr(asn["name"], "")),
		Country: jsStringOr(asn["as_country"], jsStringOr(asn["country"], "")),
		Range:   jsStringOr(asn["as_range"], jsStringOr(asn["range"], "")),
	})
}

// asnNumber reads the "AS15169" form the enricher emits, stripping the prefix
// case-insensitively. A bare "AS" strips to "" — falsy in JavaScript — and
// therefore falls through to the legacy `number` key, whereas an unparseable
// "ASXYZ" does not fall through: it drops the number entirely.
//
// The wire type is *int, so a fractional AS number would be truncated here where
// the TypeScript kept it. No probe emits one.
func asnNumber(asn map[string]any) *int {
	if raw, ok := jsString(asn["as_number"]); ok {
		if stripped := stripASPrefix(raw); stripped != "" {
			if n, ok := jsNumber(stripped); ok {
				return intPtr(int(n))
			}
			return nil
		}
	}
	if raw, ok := asn["number"]; ok {
		if n, ok := jsNumber(raw); ok {
			return intPtr(int(n))
		}
	}
	return nil
}

func stripASPrefix(value string) string {
	if len(value) >= 2 && (value[0] == 'A' || value[0] == 'a') && (value[1] == 'S' || value[1] == 's') {
		return value[2:]
	}
	return value
}

func normalizeHTTP(record map[string]any) *api.HTTP {
	return present(api.HTTP{
		URL:        jsStringOr(record["url"], ""),
		Scheme:     jsStringOr(record["scheme"], ""),
		Port:       truncated(record, "port"),
		StatusCode: truncated(record, "status_code"),
		// These five bypass the non-empty-string guard, so "" survives here where
		// every other string field would be dropped. That asymmetry is why they are
		// pointers on the wire type: a plain string could not tell "" from absent.
		Title:        rawStringPtr(record["title"]),
		Webserver:    rawStringPtr(record["webserver"]),
		ContentType:  rawStringPtr(record["content_type"]),
		Location:     rawStringPtr(record["location"]),
		ResponseTime: rawStringPtr(record["time"]),
		KnownPaths:   jsStrings(record["known_paths"]),
		LoginMethods: jsStrings(record["login_methods"]),
		Failed:       jsBoolPtr(record["failed"]),
	})
}

func normalizeTLS(value any) *api.TLS {
	tls := jsObject(value)
	if tls == nil {
		return nil
	}
	// fingerprint_hash arrives either as a plain digest string or as a map of
	// algorithms, of which only sha256 is kept.
	hash := jsStringPtr(tls["fingerprint_hash"])
	if hash == nil {
		hash = jsStringPtr(jsObject(tls["fingerprint_hash"])["sha256"])
	}
	return present(api.TLS{
		TLSVersion:          jsStringPtr(tls["tls_version"]),
		Cipher:              jsStringPtr(tls["cipher"]),
		SubjectDN:           jsStringPtr(tls["subject_dn"]),
		SubjectCN:           jsStringPtr(tls["subject_cn"]),
		SubjectOrg:          jsStrings(tls["subject_org"]),
		SubjectAN:           jsStrings(tls["subject_an"]),
		IssuerDN:            jsStringPtr(tls["issuer_dn"]),
		IssuerCN:            jsStringPtr(tls["issuer_cn"]),
		IssuerOrg:           jsStrings(tls["issuer_org"]),
		NotBefore:           jsStringPtr(tls["not_before"]),
		NotAfter:            jsStringPtr(tls["not_after"]),
		Serial:              jsStringPtr(tls["serial"]),
		Expired:             jsBoolPtr(tls["expired"]),
		SelfSigned:          jsBoolPtr(tls["self_signed"]),
		Mismatched:          jsBoolPtr(tls["mismatched"]),
		Revoked:             jsBoolPtr(tls["revoked"]),
		Untrusted:           jsBoolPtr(tls["untrusted"]),
		WildcardCertificate: jsBoolPtr(tls["wildcard_certificate"]),
		FingerprintHash:     hash,
	})
}

func normalizeCPE(value any) []api.CPE {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	var out []api.CPE
	for _, item := range items {
		if raw, ok := item.(string); ok {
			out = append(out, bareCPE(raw))
			continue
		}
		entry := jsObject(item)
		cpe, ok := jsString(entry["cpe"])
		if !ok {
			continue
		}
		out = append(out, api.CPE{
			CPE:     cpe,
			Product: jsStringPtr(entry["product"]),
			Vendor:  jsStringPtr(entry["vendor"]),
		})
	}
	return out
}

// bareCPE splits a CPE URI on ":" and reads segment 3 as the vendor and segment
// 4 as the product. That is positionally wrong for the 4-segment `cpe:/a:` form
// — `cpe:/a:apache:httpd` yields vendor "httpd" and no product at all — but it
// is what wrote the stored inventory, so it is reproduced rather than fixed.
//
// The segments also skip the non-empty-string guard, so an empty segment is kept
// as "": another reason Product and Vendor are pointers.
func bareCPE(value string) api.CPE {
	parts := strings.Split(value, ":")
	out := api.CPE{CPE: value}
	if len(parts) > 3 {
		out.Vendor = &parts[3]
	}
	if len(parts) > 4 {
		out.Product = &parts[4]
	}
	return out
}

// present mirrors the TypeScript `defined()` guard: a section in which every
// field came back undefined collapses to an absent section, not to `{}`.
// Reflection is the honest translation, because "nothing was set" is exactly the
// Go zero value for these structs — every optional field is a pointer or a slice.
// api.CDN is the one type it must not be used on, since a CDN with only
// `enabled: false` is still a section the TypeScript emitted.
func present[T any](value T) *T {
	if reflect.ValueOf(value).IsZero() {
		return nil
	}
	return &value
}

func intPtr(value int) *int { return &value }

func isTrue(value any) bool {
	flag, ok := value.(bool)
	return ok && flag
}

// jsObject mirrors `object()`: a JSON object, never an array and never null.
// Reading a key from the nil map it returns is legal, which stands in for the
// optional chaining of the original.
func jsObject(value any) map[string]any {
	object, _ := value.(map[string]any)
	return object
}

// jsString mirrors `string()`: a string is only usable when it is non-empty.
func jsString(value any) (string, bool) {
	text, ok := value.(string)
	if !ok || text == "" {
		return "", false
	}
	return text, true
}

func jsStringOr(value any, fallback string) string {
	if text, ok := jsString(value); ok {
		return text
	}
	return fallback
}

func jsStringPtr(value any) *string {
	text, ok := jsString(value)
	if !ok {
		return nil
	}
	return &text
}

// rawStringPtr keeps any string, "" included. Only the five HTTP fields that
// bypassed the guard in the original may use it.
func rawStringPtr(value any) *string {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	return &text
}

func jsBoolPtr(value any) *bool {
	flag, ok := value.(bool)
	if !ok {
		return nil
	}
	return &flag
}

// jsStrings mirrors `strings()`: keep the string members, dedupe, sort.
//
// The sort is JavaScript's bare Array.prototype.sort, which orders by code unit
// — NOT a locale collation. This is the last sort applied on the way to disk, so
// it is the order the inventory holds: login methods persist as
// ["NTLM", "Negotiate"] even though discovery derived them the other way round
// with localeCompare. See UniqueCollated in select.go for that other order.
func jsStrings(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	seen := make(map[string]bool, len(items))
	var out []string
	for _, item := range items {
		text, ok := item.(string)
		if !ok || seen[text] {
			continue
		}
		seen[text] = true
		out = append(out, text)
	}
	sort.Strings(out)
	return out
}

// jsPorts mirrors `integers()`: coerce, keep whole numbers inside 1–65535,
// dedupe, sort ascending.
func jsPorts(value any) []int {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	seen := make(map[int]bool, len(items))
	var out []int
	for _, item := range items {
		number, ok := jsNumber(item)
		if !ok || number != math.Trunc(number) || number < 1 || number > 65535 {
			continue
		}
		port := int(number)
		if seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	sort.Ints(out)
	return out
}

// truncated reads a numeric field and truncates toward zero, the way Math.trunc
// does. A missing key is undefined rather than null, which is why presence is
// checked separately: Number(undefined) is NaN but Number(null) is 0.
func truncated(record map[string]any, key string) int {
	raw, ok := record[key]
	if !ok {
		return 0
	}
	number, ok := jsNumber(raw)
	if !ok {
		return 0
	}
	return int(math.Trunc(number))
}

// jsInteger mirrors `integer()` from discovery-profile.ts: Number() coercion
// followed by Number.isInteger, with no range guard.
func jsInteger(record map[string]any, key string) (int, bool) {
	raw, ok := record[key]
	if !ok {
		return 0, false
	}
	number, ok := jsNumber(raw)
	if !ok || number != math.Trunc(number) {
		return 0, false
	}
	return int(number), true
}

// jsNumber mirrors `number()`: JavaScript's Number() coercion followed by
// Number.isFinite. Coercion is not Go's: null is 0, a bool is 0 or 1, "" is 0,
// and a one-element array takes the value of its member because String() of it
// is that member's text.
func jsNumber(value any) (float64, bool) {
	number, ok := coerceNumber(value)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	return number, true
}

func coerceNumber(value any) (float64, bool) {
	switch typed := value.(type) {
	case nil:
		return 0, true
	case bool:
		if typed {
			return 1, true
		}
		return 0, true
	case float64:
		return typed, true
	case string:
		return parseJSNumber(typed)
	case []any:
		switch len(typed) {
		case 0:
			return 0, true
		case 1:
			return coerceNumber(typed[0])
		default:
			// String([1, 2]) is "1,2", which is not a numeric literal.
			return 0, false
		}
	}
	return 0, false
}

// parseJSNumber implements the StringNumericLiteral grammar closely enough for
// probe output: whitespace is trimmed, "" is zero, and 0x/0o/0b literals parse
// while Go-only spellings such as underscores and hexadecimal floats do not.
func parseJSNumber(value string) (float64, bool) {
	text := strings.TrimFunc(value, isJSWhitespace)
	if text == "" {
		return 0, true
	}
	if len(text) > 2 && text[0] == '0' {
		if base := radix(text[1]); base != 0 {
			digits, err := strconv.ParseUint(text[2:], base, 64)
			if err != nil {
				return 0, false
			}
			return float64(digits), true
		}
	}
	if strings.ContainsAny(text, "_xXpP") {
		return 0, false
	}
	number, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return 0, false
	}
	return number, true
}

// isJSWhitespace covers the WhiteSpace and LineTerminator productions the
// literal grammar allows to surround a number; U+FEFF is whitespace to
// JavaScript but not to unicode.IsSpace.
func isJSWhitespace(r rune) bool {
	return unicode.IsSpace(r) || r == '\uFEFF'
}

func radix(marker byte) int {
	switch marker {
	case 'x', 'X':
		return 16
	case 'o', 'O':
		return 8
	case 'b', 'B':
		return 2
	}
	return 0
}
