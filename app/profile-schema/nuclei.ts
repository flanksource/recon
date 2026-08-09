import {
  booleanOption,
  enumList,
  enumOption,
  integerOption,
  stringList,
  stringOption,
  type ProfileSchemaSection,
} from "./types.ts";

const SOURCE = "https://github.com/projectdiscovery/nuclei#command-line-flags";
const protocols = [
  "dns",
  "file",
  "http",
  "headless",
  "tcp",
  "workflow",
  "ssl",
  "websocket",
  "whois",
  "code",
  "javascript",
];
const severities = ["info", "low", "medium", "high", "critical", "unknown"];

export const nucleiProfileSections: ProfileSchemaSection[] = [
  {
    id: "templates",
    title: "Templates",
    description: "Choose template sources and opt in to protocol capabilities.",
    sourceUrl: SOURCE,
    properties: {
      "new-templates": booleanOption(
        "New templates only",
        "Run templates added in the latest templates release.",
      ),
      "automatic-scan": booleanOption(
        "Automatic scan",
        "Map detected technologies to template tags automatically.",
      ),
      templates: stringList(
        "Templates",
        "Template files or directories to run.",
      ),
      workflows: stringList(
        "Workflows",
        "Workflow files or directories to run.",
      ),
      "no-strict-syntax": booleanOption(
        "Disable strict syntax",
        "Allow templates that do not pass strict syntax checks.",
      ),
      code: booleanOption("Code templates", "Enable code protocol templates."),
      file: booleanOption("File templates", "Enable file protocol templates."),
      "enable-self-contained": booleanOption(
        "Self-contained templates",
        "Enable self-contained templates.",
      ),
      "enable-global-matchers": booleanOption(
        "Global matchers",
        "Enable global matcher templates.",
      ),
      "disable-unsigned-templates": booleanOption(
        "Require signed templates",
        "Disable unsigned templates and templates with mismatched signatures.",
      ),
    },
  },
  {
    id: "filtering",
    title: "Filtering",
    description:
      "Select or exclude templates by metadata, protocol, and matcher.",
    sourceUrl: SOURCE,
    properties: {
      author: stringList("Authors", "Template authors to include."),
      tags: stringList("Tags", "Template tags to include."),
      "exclude-tags": stringList("Excluded tags", "Template tags to exclude."),
      "include-tags": stringList(
        "Forced tags",
        "Tags that run even when excluded elsewhere.",
      ),
      "template-id": stringList(
        "Template IDs",
        "Template IDs or wildcard patterns to include.",
      ),
      "exclude-id": stringList(
        "Excluded template IDs",
        "Template IDs to exclude.",
      ),
      "include-templates": stringList(
        "Forced templates",
        "Templates that run even when excluded elsewhere.",
      ),
      "exclude-templates": stringList(
        "Excluded templates",
        "Template files or directories to exclude.",
      ),
      "exclude-matchers": stringList(
        "Excluded matchers",
        "Template matcher names to suppress.",
      ),
      severity: enumList(
        "Severities",
        "Severities to include. Empty means all severities.",
        severities,
      ),
      "exclude-severity": enumList(
        "Excluded severities",
        "Severities to exclude.",
        severities,
      ),
      type: enumList(
        "Protocol types",
        "Template protocol types to include. Empty means all types.",
        protocols,
      ),
      "exclude-type": enumList(
        "Excluded protocol types",
        "Template protocol types to exclude.",
        protocols,
      ),
      "template-condition": stringList(
        "Template conditions",
        "Expression conditions applied to template metadata.",
      ),
    },
  },
  {
    id: "network",
    title: "HTTP & network",
    description:
      "Control redirects, transport behavior, headers, and network boundaries.",
    sourceUrl: SOURCE,
    properties: {
      "follow-redirects": booleanOption(
        "Follow redirects",
        "Follow HTTP redirects globally.",
      ),
      "follow-host-redirects": booleanOption(
        "Same-host redirects",
        "Follow redirects only when they remain on the same host.",
      ),
      "max-redirects": integerOption(
        "Maximum redirects",
        "Maximum redirects per request. Nuclei defaults to 10.",
        {
          minimum: 0,
        },
      ),
      "disable-redirects": booleanOption(
        "Disable redirects",
        "Disable HTTP redirect handling.",
      ),
      header: stringList(
        "Headers",
        "Headers or cookies in Header: value form. Do not store credentials here.",
      ),
      resolvers: stringOption("Resolver file", "Path to a DNS resolver list."),
      "system-resolvers": booleanOption(
        "System resolver fallback",
        "Use system DNS resolution when configured resolvers fail.",
      ),
      "disable-clustering": booleanOption(
        "Disable clustering",
        "Do not combine identical requests across templates.",
      ),
      passive: booleanOption(
        "Passive mode",
        "Process supplied HTTP responses without active requests.",
      ),
      "force-http2": booleanOption(
        "Force HTTP/2",
        "Force HTTP/2 for requests.",
      ),
      "env-vars": booleanOption(
        "Environment variables",
        "Allow environment variables in templates.",
      ),
      "client-cert": stringOption(
        "Client certificate",
        "Path to a PEM client certificate.",
      ),
      "client-key": stringOption(
        "Client key",
        "Path to the matching PEM private key. Do not commit the key itself.",
      ),
      "client-ca": stringOption(
        "Client CA",
        "Path to a PEM certificate authority.",
      ),
      sni: stringOption(
        "TLS SNI",
        "TLS server name override. Defaults to the input domain.",
      ),
      "dialer-keep-alive": stringOption(
        "Keep-alive",
        "Network keep-alive duration, such as 30s.",
      ),
      "allow-local-file-access": booleanOption(
        "Local file access",
        "Allow payload files outside the templates directory.",
      ),
      "restrict-local-network-access": booleanOption(
        "Block private networks",
        "Prevent connections to local and private networks.",
      ),
      interface: stringOption(
        "Network interface",
        "Network interface used for scans.",
      ),
      "source-ip": stringOption(
        "Source IP",
        "Source IP address used for network scans.",
      ),
      "response-size-read": integerOption(
        "Response read limit",
        "Maximum response bytes read into memory.",
        { minimum: 1 },
      ),
      "response-size-save": integerOption(
        "Response save limit",
        "Maximum response bytes written to results.",
        { minimum: 1 },
      ),
      "tls-impersonate": booleanOption(
        "TLS impersonation",
        "Randomize the experimental TLS client hello fingerprint.",
      ),
    },
  },
  {
    id: "fuzzing",
    title: "DAST & fuzzing",
    description:
      "Intrusive controls. Enabling these can send exploit payloads to targets.",
    sourceUrl: SOURCE,
    properties: {
      dast: booleanOption(
        "DAST",
        "Enable DAST fuzzing templates. This sends malicious payloads.",
      ),
      "fuzzing-type": enumOption(
        "Fuzzing type",
        "How payloads modify parameter values.",
        ["replace", "prefix", "postfix", "infix"],
      ),
      "fuzzing-mode": enumOption(
        "Fuzzing mode",
        "Whether fuzzing changes one or multiple parameters.",
        ["multiple", "single"],
      ),
      "fuzz-param-frequency": integerOption(
        "Parameter frequency",
        "Skip an uninteresting parameter after this many occurrences. Nuclei defaults to 10.",
        { minimum: 1 },
      ),
      "fuzz-aggression": enumOption(
        "Aggression",
        "Payload count and intensity.",
        ["low", "medium", "high"],
      ),
      "fuzz-scope": stringList(
        "In-scope URLs",
        "Regular expressions that the fuzzer may follow.",
      ),
      "fuzz-out-scope": stringList(
        "Out-of-scope URLs",
        "Regular expressions excluded from the fuzzer.",
      ),
      "display-fuzz-points": booleanOption(
        "Display fuzz points",
        "Show fuzz points for debugging.",
      ),
      "attack-type": enumOption(
        "Payload combinations",
        "Combination strategy for template payloads.",
        ["batteringram", "pitchfork", "clusterbomb"],
      ),
    },
  },
  {
    id: "performance",
    title: "Performance",
    description: "Bound request rate, parallelism, retries, and scan strategy.",
    sourceUrl: SOURCE,
    properties: {
      "rate-limit": integerOption(
        "Requests per second",
        "Global request limit. Nuclei defaults to 150.",
        { minimum: 1 },
      ),
      "rate-limit-duration": stringOption(
        "Rate-limit window",
        "Window for the request limit, such as 1s.",
      ),
      "per-host-rate-limit": booleanOption(
        "Per-host rate limit",
        "Apply the rate limit per host instead of globally.",
      ),
      "bulk-size": integerOption(
        "Host bulk size",
        "Hosts analyzed in parallel per template. Default: 25.",
        { minimum: 1 },
      ),
      concurrency: integerOption(
        "Template concurrency",
        "Templates executed in parallel. Default: 25.",
        { minimum: 1 },
      ),
      "headless-bulk-size": integerOption(
        "Headless host bulk",
        "Hosts analyzed in parallel per headless template. Default: 10.",
        { minimum: 1 },
      ),
      "headless-concurrency": integerOption(
        "Headless concurrency",
        "Headless templates executed in parallel. Default: 10.",
        { minimum: 1 },
      ),
      "js-concurrency": integerOption(
        "JavaScript concurrency",
        "Concurrent JavaScript runtimes. Default: 120.",
        { minimum: 1 },
      ),
      "payload-concurrency": integerOption(
        "Payload concurrency",
        "Payloads executed in parallel per template. Default: 25.",
        { minimum: 1 },
      ),
      "probe-concurrency": integerOption(
        "HTTP probe concurrency",
        "Concurrent httpx probes for non-URL input. Default: 50.",
        { minimum: 1 },
      ),
      "template-loading-concurrency": integerOption(
        "Template loading",
        "Concurrent template loading operations. Default: 50.",
        { minimum: 1 },
      ),
      timeout: integerOption(
        "Request timeout",
        "Request timeout in seconds. Default: 10.",
        { minimum: 1 },
      ),
      retries: integerOption(
        "Retries",
        "Retries after a failed request. Default: 1.",
        { minimum: 0 },
      ),
      "max-host-error": integerOption(
        "Host error limit",
        "Skip a host after this many errors. Default: 30.",
        { minimum: 1 },
      ),
      "no-mhe": booleanOption(
        "Disable host error limit",
        "Never skip a host based on its error count.",
      ),
      "stop-at-first-match": booleanOption(
        "Stop at first match",
        "Stop HTTP requests after the first match; may alter workflow logic.",
      ),
      stream: booleanOption(
        "Stream input",
        "Process input without sorting it first.",
      ),
      "scan-strategy": enumOption(
        "Scan strategy",
        "Order hosts and templates are scanned.",
        ["auto", "host-spray", "template-spray"],
      ),
      "input-read-timeout": stringOption(
        "Input timeout",
        "Maximum wait for input, such as 3m.",
      ),
      "leave-default-ports": booleanOption(
        "Keep default ports",
        "Retain :80 and :443 in HTTP host values.",
      ),
      "no-httpx": booleanOption(
        "Disable httpx probing",
        "Do not probe non-URL input with httpx.",
      ),
      "preflight-portscan": booleanOption(
        "Preflight port scan",
        "Resolve and port-scan targets before template execution.",
      ),
      "max-time": stringOption(
        "Maximum runtime",
        "Terminate the scan after a duration such as 1h or 30m.",
      ),
    },
  },
  {
    id: "headless",
    title: "Headless browser",
    description: "Configure templates that execute in Chromium.",
    sourceUrl: SOURCE,
    properties: {
      headless: booleanOption(
        "Enable headless",
        "Enable templates that require a browser.",
      ),
      "page-timeout": integerOption(
        "Page timeout",
        "Seconds to wait for each page. Default: 20.",
        { minimum: 1 },
      ),
      "show-browser": booleanOption(
        "Show browser",
        "Display the browser window during the scan.",
      ),
      "headless-options": stringList(
        "Chrome options",
        "Additional Chromium command-line options.",
      ),
      "system-chrome": booleanOption(
        "System Chrome",
        "Use the locally installed Chrome browser.",
      ),
      "cdp-endpoint": stringOption(
        "CDP endpoint",
        "Remote Chrome DevTools Protocol endpoint.",
      ),
    },
  },
  {
    id: "runtime",
    title: "Runtime & telemetry",
    description:
      "Control updates, progress statistics, metrics, and honeypot detection.",
    sourceUrl: SOURCE,
    properties: {
      "disable-update-check": booleanOption(
        "Disable update checks",
        "Do not check for engine or template updates.",
      ),
      stats: booleanOption("Statistics", "Display scan statistics."),
      "stats-interval": integerOption(
        "Statistics interval",
        "Seconds between statistics updates. Default: 5.",
        { minimum: 1 },
      ),
      "http-stats": booleanOption(
        "HTTP status capture",
        "Capture experimental HTTP statistics.",
      ),
      "metrics-port": integerOption(
        "Metrics port",
        "Port for the metrics endpoint. Default: 9092.",
        {
          minimum: 1,
          maximum: 65535,
        },
      ),
      "honeypot-detect": booleanOption(
        "Honeypot detection",
        "Flag hosts with a suspicious concentration of matches.",
      ),
      "honeypot-threshold": integerOption(
        "Honeypot threshold",
        "Distinct template IDs required to flag a host. Default: 15.",
        { minimum: 1 },
      ),
      "suppress-honeypot": booleanOption(
        "Suppress honeypots",
        "Suppress findings for hosts flagged as honeypots.",
      ),
    },
  },
];
