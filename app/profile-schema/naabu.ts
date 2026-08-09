import {
  booleanOption,
  enumList,
  enumOption,
  integerOption,
  stringList,
  stringOption,
  type ProfileSchemaSection,
} from "./types.ts";

const SOURCE = "https://github.com/projectdiscovery/naabu#usage";

export const naabuProfileSections: ProfileSchemaSection[] = [
  {
    id: "ports",
    title: "Ports & targets",
    description: "Choose the port range and bound broad scans of shared infrastructure.",
    sourceUrl: SOURCE,
    properties: {
      port: stringOption("Ports", "Ports or ranges to scan, such as 80,443,8000-8100."),
      "top-ports": enumOption("Top ports", "Use Naabu's ranked port set.", ["100", "1000", "full"]),
      "exclude-ports": stringList("Excluded ports", "Ports, ranges, or files excluded from the scan."),
      "ports-file": stringList("Port files", "Files containing ports to scan."),
      "port-threshold": integerOption(
        "Port threshold",
        "Stop scanning a host after this many open ports are found.",
        { minimum: 1 },
      ),
      "exclude-cdn": booleanOption(
        "Limit CDN scans",
        "Scan only ports 80 and 443 when the address belongs to a known CDN or WAF.",
      ),
      "display-cdn": booleanOption("Show CDN", "Include detected CDN details in results."),
    },
  },
  {
    id: "network",
    title: "Network & services",
    description: "Control address selection, scan transport, DNS, and service detection.",
    sourceUrl: SOURCE,
    properties: {
      "scan-all-ips": booleanOption("Scan every IP", "Scan every address resolved for a hostname."),
      "ip-version": enumList("IP versions", "IP versions included in the scan.", ["4", "6"]),
      "scan-type": enumOption("Scan type", "CONNECT works without raw-socket privileges.", ["c", "s"]),
      r: stringOption("Resolvers", "Comma-separated custom DNS resolvers or a resolver file."),
      "service-discovery": booleanOption("Service discovery", "Identify services on open ports."),
      "service-version": booleanOption("Service versions", "Identify service versions when probe data is available."),
    },
  },
  {
    id: "performance",
    title: "Performance",
    description: "Bound connection rate, concurrency, timeouts, retries, and verification.",
    sourceUrl: SOURCE,
    properties: {
      c: integerOption("Workers", "Internal worker count. Naabu defaults to 25.", { minimum: 1 }),
      rate: integerOption("Packets per second", "Global scan rate limit.", { minimum: 1 }),
      retries: integerOption("Retries", "Number of scan attempts per port.", { minimum: 1 }),
      timeout: stringOption("Timeout", "Port timeout such as 1s or 1500ms."),
      "warm-up-time": integerOption("Warm-up time", "Seconds between scan phases.", { minimum: 0 }),
      verify: booleanOption("Verify ports", "Confirm discovered ports with a TCP connection."),
    },
  },
];
