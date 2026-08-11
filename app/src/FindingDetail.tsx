import { useState, type ReactNode } from "react";
import { Badge, CodeBlock, Properties, Tabs, type TabItem } from "@flanksource/clicky-ui";
import { severityBadge } from "./scanColumns";
import type { Finding } from "./types";

// The engine's own record. Nuclei nests most of what an operator needs to
// triage — description, impact, CVE classification, template path — under
// `info`, and none of it survives the normalised columns, so the detail view
// reads the raw record rather than asking the API for a second shape.
function record(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function text(value: unknown): string | undefined {
  if (typeof value === "string") return value.trim() || undefined;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return undefined;
}

function list(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map(text).filter((entry): entry is string => entry !== undefined);
  }
  const single = text(value);
  return single ? [single] : [];
}

function Prose({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-semibold uppercase text-muted-foreground">{title}</span>
      <p className="whitespace-pre-wrap text-sm text-foreground">{body}</p>
    </div>
  );
}

function Evidence({ title, language, source }: { title: string; language: string; source: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-semibold uppercase text-muted-foreground">{title}</span>
      <CodeBlock
        language={language}
        source={source}
        copyable
        downloadable
        className="max-h-80 overflow-auto"
      />
    </div>
  );
}

const NVD = "https://nvd.nist.gov/vuln/detail/";

// CVE, CVSS, CWE and EPSS read as one risk statement, so they sit together as
// badges rather than as four more rows in the property list.
function Classification({ classification }: { classification: Record<string, unknown> }) {
  const cves = list(classification["cve-id"]);
  const cwes = list(classification["cwe-id"]);
  const score = text(classification["cvss-score"]);
  const metrics = text(classification["cvss-metrics"]);
  const epss = text(classification["epss-score"]);
  const percentile = text(classification["epss-percentile"]);
  const cpe = text(classification.cpe);

  if (!cves.length && !cwes.length && !score && !epss && !cpe) return null;

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {cves.map((cve) => (
        <Badge
          key={cve}
          variant="metric"
          tone="danger"
          label="CVE"
          value={cve.toUpperCase()}
          href={`${NVD}${cve.toUpperCase()}`}
          target="_blank"
          rel="noreferrer"
        />
      ))}
      {score && (
        <span title={metrics}>
          <Badge variant="metric" tone="warning" label="CVSS" value={score} />
        </span>
      )}
      {cwes.map((cwe) => (
        <Badge key={cwe} variant="metric" label="CWE" value={cwe.toUpperCase()} />
      ))}
      {epss && (
        <span title="Exploit Prediction Scoring System">
          <Badge variant="metric" label="EPSS" value={percentile ? `${epss} (p${percentile})` : epss} />
        </span>
      )}
      {cpe && <Badge variant="metric" label="CPE" value={cpe} truncate="auto" maxWidth={40} />}
    </div>
  );
}

function Mono({ children }: { children: ReactNode }) {
  return <code className="break-all text-xs">{children}</code>;
}

function overviewProperties(
  finding: Finding,
  raw: Record<string, unknown>,
  info: Record<string, unknown>,
): { key: string; value: ReactNode; hidden?: boolean }[] {
  const metadata = record(info.metadata);
  const authors = list(info.author);
  const matchedAt = finding.matchedAt || text(raw["matched-at"]);
  const templatePath = text(raw["template-path"]);
  const url = text(raw.url);
  const ip = text(raw.ip);
  const port = text(raw.port);
  const matcherStatus = raw["matcher-status"];

  return [
    { key: "Severity", value: severityBadge(finding.severity) },
    {
      key: "Template",
      value: (
        <div className="flex flex-col">
          <Mono>{finding.templateId}</Mono>
          {templatePath && <span className="text-[11px] text-muted-foreground">{templatePath}</span>}
        </div>
      ),
    },
    { key: "Type", value: <Mono>{finding.type ?? text(raw.type) ?? "—"}</Mono> },
    { key: "Matcher", value: <Mono>{finding.matcherName}</Mono>, hidden: !finding.matcherName },
    {
      key: "Matcher status",
      value: <Mono>{String(matcherStatus)}</Mono>,
      hidden: typeof matcherStatus !== "boolean",
    },
    { key: "Host", value: <Mono>{finding.host || text(raw.host) || "—"}</Mono> },
    {
      key: "Address",
      value: <Mono>{[ip, port].filter(Boolean).join(":")}</Mono>,
      hidden: !ip && !port,
    },
    {
      key: "Matched at",
      value: matchedAt ? (
        <a
          href={matchedAt}
          target="_blank"
          rel="noreferrer"
          className="break-all text-xs text-primary hover:underline"
        >
          {matchedAt}
        </a>
      ) : null,
      hidden: !matchedAt,
    },
    { key: "URL", value: <Mono>{url}</Mono>, hidden: !url || url === matchedAt },
    { key: "Tags", value: <Mono>{finding.tags.join(", ")}</Mono>, hidden: !finding.tags.length },
    { key: "Authors", value: <Mono>{authors.join(", ")}</Mono>, hidden: !authors.length },
    {
      key: "Timestamp",
      value: <Mono>{finding.timestamp ?? text(raw.timestamp)}</Mono>,
      hidden: !finding.timestamp && !text(raw.timestamp),
    },
    {
      key: "Scan",
      value: (
        <Mono>
          {finding.scanId} · line {finding.lineNo}
        </Mono>
      ),
    },
    ...Object.entries(metadata).map(([key, value]) => ({
      key: `metadata.${key}`,
      value: <Mono>{text(value) ?? JSON.stringify(value)}</Mono>,
    })),
  ];
}

function Overview({ finding, raw }: { finding: Finding; raw: Record<string, unknown> }) {
  const info = record(raw.info);
  const description = text(info.description);
  const impact = text(info.impact);
  const remediation = finding.remediation ?? text(info.remediation);
  const references = finding.reference?.length ? finding.reference : list(info.reference);
  const error = text(raw.error);

  return (
    <div className="flex flex-col gap-3">
      <Classification classification={record(info.classification)} />
      {error && (
        <p role="alert" className="rounded border border-destructive/40 bg-destructive/5 p-2 text-sm text-destructive">
          {error}
        </p>
      )}
      {description && <Prose title="Description" body={description} />}
      {impact && <Prose title="Impact" body={impact} />}
      {remediation && <Prose title="Remediation" body={remediation} />}
      {finding.extracted?.length ? (
        <div className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase text-muted-foreground">Extracted</span>
          <pre className="overflow-x-auto rounded bg-muted/50 p-2 text-xs">
            {finding.extracted.join("\n")}
          </pre>
        </div>
      ) : null}
      {references.length ? (
        <div className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase text-muted-foreground">References</span>
          <ul className="list-inside list-disc text-xs">
            {references.map((reference) => (
              <li key={reference}>
                <a href={reference} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                  {reference}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <Properties<ReactNode>
        items={overviewProperties(finding, raw, info)}
        renderValue={(_key, value) => value}
        renderLabel={(key) => key.replace(/^metadata\./, "")}
        density="compact"
        showDensityMenu={false}
      />
    </div>
  );
}

// `request` and `response` are HTTP wire text only for http-family templates.
// A javascript or code template puts its own source in `request` and whatever
// it exported in `response`, so highlighting either as HTTP misreads it.
const REQUEST_LANGUAGE: Record<string, string> = { javascript: "javascript", code: "bash" };

export function FindingDetail({ finding }: { finding: Finding }) {
  const raw = record(finding.raw);
  const requestLanguage = REQUEST_LANGUAGE[finding.type ?? ""] ?? "http";
  const evidence = [
    finding.curl && { title: "Reproduce (curl)", language: "bash", source: finding.curl },
    finding.request && { title: "Request", language: requestLanguage, source: finding.request },
    finding.response && {
      title: "Response",
      language: requestLanguage === "http" ? "http" : "text",
      source: finding.response,
    },
  ].filter((entry): entry is { title: string; language: string; source: string } => Boolean(entry));

  // Engines that match on a parsed document rather than a transaction (dns,
  // ssl, file) carry no request or response at all — an empty Evidence tab
  // would say "look here" about nothing.
  const tabs: TabItem[] = [
    { id: "overview", label: "Overview" },
    ...(evidence.length ? [{ id: "evidence", label: "Evidence", count: evidence.length }] : []),
    { id: "raw", label: "Raw JSON" },
  ];
  const [tab, setTab] = useState("overview");

  return (
    // `w-0 min-w-full` keeps the detail out of the table's width calculation:
    // the cell spans every column, so a wide request body or JSON tree would
    // otherwise stretch the table past its scroll container and shift every
    // column the moment a row is expanded.
    <div className="flex w-0 min-w-full flex-col gap-3 px-4 py-3">
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {tab === "overview" && <Overview finding={finding} raw={raw} />}
      {tab === "evidence" && (
        <div className="flex flex-col gap-3">
          {evidence.map((entry) => (
            <Evidence key={entry.title} {...entry} />
          ))}
        </div>
      )}
      {/* The whole finding, not just `raw`: what the engine reported and what
          the API normalised it to are both evidence, and copying one without
          the other loses the link between them. */}
      {tab === "raw" && (
        <CodeBlock
          language="json"
          source={JSON.stringify(finding, null, 2)}
          jsonDefaultOpenDepth={2}
          copyable
          downloadable
          className="max-h-96 overflow-auto"
        />
      )}
    </div>
  );
}
