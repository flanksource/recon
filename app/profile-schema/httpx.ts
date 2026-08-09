import {
  booleanOption,
  enumOption,
  integerOption,
  stringList,
  stringOption,
  type ProfileSchemaSection,
} from "./types.ts";

const SOURCE =
  "https://github.com/projectdiscovery/httpx/blob/dev/runner/options.go#L383";

export const httpxProfileSections: ProfileSchemaSection[] = [
  {
    id: "probes",
    title: "Response probes",
    description: "Choose the metadata collected for each discovered endpoint.",
    sourceUrl: SOURCE,
    properties: {
      "status-code": booleanOption(
        "Status code",
        "Collect the HTTP response status.",
      ),
      "content-length": booleanOption(
        "Content length",
        "Collect response content length.",
      ),
      "content-type": booleanOption(
        "Content type",
        "Collect the response content type.",
      ),
      location: booleanOption(
        "Redirect location",
        "Collect the Location response header.",
      ),
      favicon: booleanOption(
        "Favicon hash",
        "Calculate the mmh3 hash of /favicon.ico.",
      ),
      hash: enumOption(
        "Body hash",
        "Hash algorithm applied to the response body.",
        ["md5", "mmh3", "simhash", "sha1", "sha256", "sha512"],
      ),
      jarm: booleanOption("JARM", "Collect the JARM TLS fingerprint."),
      "response-time": booleanOption(
        "Response time",
        "Collect request latency.",
      ),
      "include-response-header": booleanOption(
        "Response headers",
        "Include response headers in JSON output for authentication discovery.",
      ),
      "line-count": booleanOption("Line count", "Count response body lines."),
      "word-count": booleanOption("Word count", "Count response body words."),
      title: booleanOption("Page title", "Collect the HTML page title."),
      "body-preview": integerOption(
        "Body preview",
        "Number of response characters included in the preview. Default: 100.",
        { minimum: 0 },
      ),
      "web-server": booleanOption(
        "Web server",
        "Collect the Server response header.",
      ),
      "tech-detect": booleanOption(
        "Technology detection",
        "Detect technologies with the Wappalyzer data set.",
      ),
      "custom-fingerprint-file": stringOption(
        "Fingerprint file",
        "Custom fingerprints used by technology detection.",
      ),
      cpe: booleanOption(
        "CPE",
        "Collect Common Platform Enumeration product details.",
      ),
      wordpress: booleanOption(
        "WordPress",
        "Detect WordPress plugins and themes.",
      ),
      method: booleanOption(
        "HTTP method",
        "Include the request method in results.",
      ),
      websocket: booleanOption("WebSocket", "Detect WebSocket support."),
      ip: booleanOption("IP address", "Collect the resolved host IP."),
      cname: booleanOption("CNAME", "Collect the host CNAME."),
      "extract-fqdn": booleanOption(
        "Extract domains",
        "Extract domains and subdomains from response bodies and headers.",
      ),
      asn: booleanOption("ASN", "Collect autonomous system information."),
      cdn: booleanOption(
        "CDN / WAF",
        "Detect the CDN or web application firewall.",
      ),
      probe: booleanOption(
        "Probe status",
        "Include success or failure of each probe.",
      ),
      "tls-grab": booleanOption(
        "TLS metadata",
        "Collect TLS certificate information.",
      ),
      pipeline: booleanOption(
        "HTTP pipelining",
        "Detect HTTP/1.1 pipeline support.",
      ),
      http2: booleanOption("HTTP/2", "Detect HTTP/2 support."),
      vhost: booleanOption("Virtual host", "Probe virtual-host behavior."),
    },
  },
  {
    id: "filters",
    title: "Matchers & filters",
    description:
      "Keep or reject discovery results using response properties and expressions.",
    sourceUrl: SOURCE,
    properties: {
      "match-code": stringOption(
        "Match status codes",
        "Comma-separated status codes to keep, such as 200,302.",
      ),
      "match-length": stringOption(
        "Match lengths",
        "Comma-separated response lengths to keep.",
      ),
      "match-line-count": stringOption(
        "Match line counts",
        "Comma-separated body line counts to keep.",
      ),
      "match-word-count": stringOption(
        "Match word counts",
        "Comma-separated body word counts to keep.",
      ),
      "match-favicon": stringList(
        "Match favicon hashes",
        "Favicon hashes to keep.",
      ),
      "match-string": stringList("Match strings", "Response strings to keep."),
      "match-regex": stringList(
        "Match regular expressions",
        "Response regular expressions to keep.",
      ),
      "match-response-time": stringOption(
        "Match response time",
        "Response-time expression such as < 1.",
      ),
      "match-condition": stringOption(
        "Match condition",
        "DSL condition that results must satisfy.",
      ),
      "extract-regex": stringList(
        "Extract expressions",
        "Regular expressions whose matches are included in output.",
      ),
      "extract-preset": stringList(
        "Extract presets",
        "Built-in extractors such as url, ipv4, and mail.",
      ),
      "filter-code": stringOption(
        "Filter status codes",
        "Comma-separated status codes to reject, such as 403,401.",
      ),
      "filter-error-page": booleanOption(
        "Filter error pages",
        "Use ML-based generic error-page detection.",
      ),
      "filter-duplicates": booleanOption(
        "Filter duplicates",
        "Keep only the first near-duplicate response.",
      ),
      "filter-length": stringOption(
        "Filter lengths",
        "Comma-separated response lengths to reject.",
      ),
      "filter-line-count": stringOption(
        "Filter line counts",
        "Comma-separated body line counts to reject.",
      ),
      "filter-word-count": stringOption(
        "Filter word counts",
        "Comma-separated body word counts to reject.",
      ),
      "filter-favicon": stringList(
        "Filter favicon hashes",
        "Favicon hashes to reject.",
      ),
      "filter-string": stringList(
        "Filter strings",
        "Response strings to reject.",
      ),
      "filter-regex": stringList(
        "Filter regular expressions",
        "Response regular expressions to reject.",
      ),
      "filter-response-time": stringOption(
        "Filter response time",
        "Response-time expression such as > 1.",
      ),
      "filter-condition": stringOption(
        "Filter condition",
        "DSL condition used to reject results.",
      ),
      strip: enumOption("Strip markup", "Remove markup before matching.", [
        "html",
        "xml",
      ]),
    },
  },
  {
    id: "network",
    title: "Requests & network",
    description:
      "Control ports, paths, redirects, DNS, headers, and TLS behavior.",
    sourceUrl: SOURCE,
    properties: {
      ports: stringList(
        "Ports",
        "Ports in nmap-style syntax, such as http:80,8080 or https:443.",
      ),
      path: stringOption("Paths", "Path or comma-separated paths to probe."),
      "probe-all-ips": booleanOption(
        "Probe every IP",
        "Probe all IPs associated with each host.",
      ),
      "tls-probe": booleanOption(
        "TLS domains",
        "Probe domains extracted from TLS certificates.",
      ),
      "csp-probe": booleanOption(
        "CSP domains",
        "Probe domains extracted from Content-Security-Policy headers.",
      ),
      resolvers: stringList(
        "Resolvers",
        "Custom DNS resolvers or resolver files.",
      ),
      allow: stringList(
        "Allowed networks",
        "IP addresses and CIDRs allowed for probing.",
      ),
      deny: stringList(
        "Denied networks",
        "IP addresses and CIDRs blocked from probing.",
      ),
      "sni-name": stringOption("TLS SNI", "Custom TLS server name."),
      "random-agent": booleanOption(
        "Random user agent",
        "Use a randomized User-Agent header.",
      ),
      "auto-referer": booleanOption(
        "Automatic Referer",
        "Set Referer to the current URL when following links.",
      ),
      header: stringList(
        "Headers",
        "Headers in Header: value form. Do not store credentials here.",
      ),
      "follow-redirects": booleanOption(
        "Follow redirects",
        "Follow HTTP redirects.",
      ),
      "max-redirects": integerOption(
        "Maximum redirects",
        "Maximum redirects per host. Default: 10.",
        { minimum: 0 },
      ),
      "follow-host-redirects": booleanOption(
        "Same-host redirects",
        "Follow redirects only on the same host.",
      ),
      "respect-hsts": booleanOption(
        "Respect HSTS",
        "Honor HSTS headers for redirects.",
      ),
      "vhost-input": booleanOption(
        "Virtual-host input",
        "Treat input as virtual hosts.",
      ),
      "leave-default-ports": booleanOption(
        "Keep default ports",
        "Retain :80 and :443 in the Host header.",
      ),
      ztls: booleanOption("ZTLS", "Use ZTLS with TLS 1.3 fallback."),
      "no-decode": booleanOption(
        "Do not decode body",
        "Keep encoded response bodies unchanged.",
      ),
      "tls-impersonate": booleanOption(
        "TLS impersonation",
        "Randomize the experimental TLS client hello fingerprint.",
      ),
      "no-fallback": booleanOption(
        "Probe HTTP and HTTPS",
        "Return both protocols instead of falling back to one.",
      ),
      "no-fallback-scheme": booleanOption(
        "Keep input scheme",
        "Probe only the protocol scheme supplied in input.",
      ),
      exclude: stringList(
        "Excluded hosts",
        "Exclude CDN, private IPs, CIDRs, IPs, or matching host expressions.",
      ),
    },
  },
  {
    id: "performance",
    title: "Performance",
    description:
      "Bound concurrency, request rate, retries, delays, and response memory.",
    sourceUrl: SOURCE,
    properties: {
      threads: integerOption(
        "Threads",
        "Concurrent worker count. httpx defaults to 50.",
        { minimum: 1 },
      ),
      "rate-limit": integerOption(
        "Requests per second",
        "Global request limit. httpx defaults to 150.",
        { minimum: 1 },
      ),
      "rate-limit-minute": integerOption(
        "Requests per minute",
        "Alternative per-minute request limit.",
        { minimum: 1 },
      ),
      stream: booleanOption(
        "Stream input",
        "Process targets without sorting first.",
      ),
      "skip-dedupe": booleanOption(
        "Skip deduplication",
        "Do not deduplicate streamed input.",
      ),
      "max-host-error": integerOption(
        "Host error limit",
        "Skip remaining paths after this many errors. Default: 30.",
        { minimum: 1 },
      ),
      retries: integerOption("Retries", "Retries after a failed request.", {
        minimum: 0,
      }),
      timeout: integerOption(
        "Timeout",
        "Request timeout in seconds. Default: 10.",
        { minimum: 1 },
      ),
      delay: stringOption(
        "Request delay",
        "Delay between requests, such as 200ms or 1s.",
      ),
      "response-size-to-save": integerOption(
        "Response save limit",
        "Maximum response bytes saved to disk.",
        { minimum: 1 },
      ),
      "response-size-to-read": integerOption(
        "Response read limit",
        "Maximum response bytes read into memory.",
        { minimum: 1 },
      ),
    },
  },
];
