package main

import "strings"

// initialisms are the segments Go convention capitalises whole. Without them a
// generator produces Uid, Http and Cvss, which read as typos beside the rest of
// the codebase and which golangci-lint's revive rules reject.
var initialisms = map[string]string{
	"api":   "API",
	"arn":   "ARN",
	"asn":   "ASN",
	"cidr":  "CIDR",
	"cpe":   "CPE",
	"cpu":   "CPU",
	"cve":   "CVE",
	"cvss":  "CVSS",
	"cwe":   "CWE",
	"dns":   "DNS",
	"dt":    "DT",
	"epss":  "EPSS",
	"guid":  "GUID",
	"http":  "HTTP",
	"https": "HTTPS",
	"id":    "ID",
	"ids":   "IDs",
	"ip":    "IP",
	"ips":   "IPs",
	"ja4":   "JA4",
	"json":  "JSON",
	"mac":   "MAC",
	"os":    "OS",
	"osint": "OSINT",
	"ou":    "OU",
	"ram":   "RAM",
	"sha":   "SHA",
	"sql":   "SQL",
	"ssl":   "SSL",
	"tls":   "TLS",
	"ttl":   "TTL",
	"uid":   "UID",
	"uids":  "UIDs",
	"uri":   "URI",
	"url":   "URL",
	"uuid":  "UUID",
	"vlan":  "VLAN",
	"vpc":   "VPC",
	"xml":   "XML",
}

// goName converts an OCSF snake_case name to an exported Go identifier.
//
// OCSF object names occasionally carry an extension prefix — `win/reg_key` —
// which is a path segment rather than part of the name, so the segment is
// folded in rather than dropped: win/reg_key becomes WinRegKey.
func goName(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	var out strings.Builder
	for _, part := range strings.Split(name, "_") {
		if part == "" {
			continue
		}
		if replacement, ok := initialisms[strings.ToLower(part)]; ok {
			out.WriteString(replacement)
			continue
		}
		out.WriteString(strings.ToUpper(part[:1]))
		out.WriteString(part[1:])
	}
	return out.String()
}

// enumConstName builds the constant for one enum member. OCSF captions are
// prose — "In Progress", "Not Applicable" — so they are folded to a single
// identifier segment rather than used verbatim.
func enumConstName(typeName, caption string, value string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == ' ', r == '-', r == '_', r == '/':
			return ' '
		default:
			return -1
		}
	}, caption)

	var suffix strings.Builder
	for _, part := range strings.Fields(cleaned) {
		suffix.WriteString(strings.ToUpper(part[:1]))
		suffix.WriteString(part[1:])
	}
	// A caption that survives as nothing printable still needs a distinct
	// constant, and the numeric value is the only thing guaranteed unique.
	if suffix.Len() == 0 {
		return typeName + "Value" + value
	}
	return typeName + suffix.String()
}

// wrapComment renders prose as a Go comment. OCSF descriptions carry HTML —
// <p>, <code>, <br> — because they are written for the schema browser.
func wrapComment(indent, text string, width int) []string {
	text = stripHTML(text)
	if text == "" {
		return nil
	}
	var lines []string
	current := indent + "//"
	for _, word := range strings.Fields(text) {
		if len(current)+1+len(word) > width && current != indent+"//" {
			lines = append(lines, current)
			current = indent + "//"
		}
		current += " " + word
	}
	if current != indent+"//" {
		lines = append(lines, current)
	}
	return lines
}

func stripHTML(text string) string {
	replacer := strings.NewReplacer(
		"<p>", "", "</p>", " ",
		"<br>", " ", "<br/>", " ",
		"<code>", "", "</code>", "",
		"<b>", "", "</b>", "",
		"<i>", "", "</i>", "",
		"<ul>", " ", "</ul>", " ",
		"<li>", " ", "</li>", " ",
		"&lt;", "<", "&gt;", ">", "&amp;", "&", "&quot;", `"`,
		"\n", " ", "\r", " ", "\t", " ",
	)
	return strings.Join(strings.Fields(replacer.Replace(text)), " ")
}
