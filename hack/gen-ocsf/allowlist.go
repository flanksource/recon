package main

// rootClass is the OCSF class recon stores a finding as.
const rootClass = "detection_finding"

// allowed is the OCSF surface recon populates — the "minimal" in a minimal OCSF
// record, kept in one reviewable place.
//
// Pruning is not an optimisation. detection_finding's transitive closure is 123
// object definitions: `evidences` alone reaches `device` (63 attributes),
// `file` (45) and `process` (30), none of which a scan engine fills. Generating
// the closure would emit thousands of lines of types nothing sets, and would
// make "minimal record" untrue on the first run.
//
// The generator fails when an allowlisted attribute names an object that is not
// itself allowlisted, and when an allowlisted attribute does not exist in the
// schema. Widening the surface is therefore a deliberate edit here rather than
// something that happens by accident on a version bump.
var allowed = map[string][]string{
	rootClass: {
		"activity_id", "activity_name",
		"category_name", "category_uid",
		"class_name", "class_uid",
		"type_name", "type_uid",
		"time",
		"metadata",
		"finding_info",
		"severity", "severity_id",
		"status", "status_code", "status_detail", "status_id",
		"cloud",
		"evidences",
		"resources",
		"remediation",
		"vulnerabilities",
		"observables",
		"unmapped",
		"impact", "impact_id",
		"risk_details",
		"is_alert",
		"message",
	},

	"metadata": {
		"version", "product", "event_code", "profiles", "uid",
		"correlation_uid", "labels", "logged_time", "original_time",
	},
	"product": {"name", "vendor_name", "version", "uid"},

	"finding_info": {
		"uid", "uid_alt", "title", "desc", "types", "src_url",
		"created_time", "first_seen_time", "last_seen_time", "modified_time",
		"data_sources",
	},

	"cloud":        {"provider", "account", "org", "region", "zone", "project_uid", "cloud_partition"},
	"account":      {"uid", "name", "type", "type_id", "labels"},
	"organization": {"uid", "name", "ou_uid", "ou_name"},

	"resource_details": {
		"uid", "uid_alt", "name", "type", "namespace", "hostname", "ip",
		"group", "labels", "region", "zone", "cloud_partition", "criticality",
		"version", "data",
	},
	"group": {"uid", "name", "type", "desc", "domain", "privileges"},

	"remediation": {"desc", "references"},

	"observable": {"name", "type", "type_id", "value"},

	// Deliberately narrow. The engines recon runs produce HTTP exchanges, a
	// URL, an affected resource and a free-form blob; they do not produce
	// processes, containers or registry keys.
	"evidences": {
		"name", "uid", "data", "url", "resources",
		"src_endpoint", "dst_endpoint",
		"http_request", "http_response",
	},
	"url": {"url_string", "scheme", "hostname", "domain", "subdomain", "port", "path", "query_string"},
	"network_endpoint": {
		"name", "hostname", "ip", "port", "uid", "domain", "svc_name", "type", "type_id",
	},
	"http_request": {
		"url", "http_method", "http_headers", "user_agent", "version",
		"body_length", "length", "uid", "args", "referrer", "x_forwarded_for",
	},
	"http_response": {
		"code", "status", "message", "content_type", "http_headers",
		"body_length", "length", "latency",
	},
	"http_header": {"name", "value"},

	"vulnerability": {
		"title", "desc", "category", "severity", "references",
		"cve", "cwe", "affected_packages", "remediation",
		"first_seen_time", "last_seen_time",
		"fix_available", "is_fix_available", "is_exploit_available",
		"vendor_name", "related_vulnerabilities",
	},
	"cve": {
		"uid", "title", "desc", "type", "references",
		"created_time", "modified_time",
		"cvss", "cwe", "cwe_uid", "cwe_url", "epss",
	},
	"cvss": {
		"version", "base_score", "overall_score", "severity",
		"vector_string", "depth", "src_url", "vendor_name",
	},
	"cwe":  {"uid", "caption", "src_url"},
	"epss": {"score", "percentile", "version", "created_time"},
	"affected_package": {
		"name", "version", "type", "type_id", "purl", "path", "license",
		"architecture", "cpe_name", "fixed_in_version", "package_manager",
		"vendor_name", "release", "epoch",
	},
}
