import { useState, type ReactNode } from "react";
import { DropdownMenu, Tabs, type TabItem } from "@flanksource/clicky-ui/components";
import { Badge, CodeBlock, Markdown, Properties } from "@flanksource/clicky-ui/data";
import { muteScopeOptions } from "./mute-prefill";
import { severityBadge } from "./scanColumns";
import {
  resourceLabel,
  severityOf,
  type Evidence as EvidenceEntry,
  type Finding,
  type OcsfVulnerability,
} from "./types";

// Whatever the engine reported that OCSF has no name for. This used to be the
// whole record: description, impact, CVE classification and template path were
// reachable only by digging through it, differently per engine. They are
// modelled attributes now, and what is left here is genuinely unnamed.
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


function unique(values: (string | undefined)[]): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))];
}

/**
 * The things a finding is about.
 *
 * A resource has two names and only one of them is worth reading: a GCP firewall
 * is `tailscale-router` with uid `1429543158501771126`. The uid is still shown,
 * because it is what a mute rule and a catalog lookup match on, but it is
 * subordinate to the name rather than standing in for it.
 */
function ResourceList({ finding }: { finding: Finding }) {
  const resources = finding.resources ?? [];
  if (resources.length === 0) {
    return <Mono>{finding.matchedAt || "—"}</Mono>;
  }

  return (
    <div className="flex flex-col gap-1">
      {resources.map((resource) => (
        <div key={`${resource.type ?? ""}/${resource.uid}`} className="flex flex-col">
          <span className="flex flex-wrap items-baseline gap-1.5">
            <span className="break-all text-xs font-medium text-foreground">
              {resourceLabel(resource)}
            </span>
            {resource.type ? <Badge size="sm">{resource.type}</Badge> : null}
            {resource.region ? <Badge size="sm">{resource.region}</Badge> : null}
          </span>
          {resource.name && resource.uid !== resource.name ? (
            <span className="break-all font-mono text-[11px] text-muted-foreground">
              {resource.uid}
            </span>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function Prose({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-semibold uppercase text-muted-foreground">{title}</span>
      <Markdown text={body} className="text-sm text-foreground" />
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
//
// Read off `vulnerabilities[]`, which is the object OCSF defines for exactly
// this. It used to come from nuclei's `raw.info.classification` — so a trivy
// CVE, which is the same fact from a different engine, rendered nothing here.
function Classification({ vulnerabilities }: { vulnerabilities: OcsfVulnerability[] }) {
  const cves = unique(vulnerabilities.map((entry) => entry.cve?.uid));
  const cwes = unique(
    vulnerabilities.flatMap((entry) => [entry.cwe?.uid, text(record(entry.cve).cwe_uid)]),
  );
  const cvss = vulnerabilities.flatMap((entry) => entry.cve?.cvss ?? []).map(record);
  const score = text(cvss[0]?.base_score);
  const metrics = text(cvss[0]?.vector_string);
  const scoring = record(record(vulnerabilities[0]?.cve).epss);
  const epss = text(scoring.score);
  const percentile = text(scoring.percentile);
  const cpe = text(record(vulnerabilities[0]?.affected_packages?.[0]).cpe_name);

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

/**
 * Which package is affected and what fixes it.
 *
 * The one thing a vulnerability finding is actually about, and until the record
 * modelled it the answer lived in the title and a tag — so "upgrade Django to
 * 2.2.9" had to be read out of prose rather than shown.
 */
function AffectedPackages({ vulnerabilities }: { vulnerabilities: OcsfVulnerability[] }) {
  const packages = vulnerabilities.flatMap((entry) => entry.affected_packages ?? []);
  if (packages.length === 0) return null;
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-semibold uppercase text-muted-foreground">Affected</span>
      <div className="flex flex-wrap items-center gap-1.5">
        {packages.map((entry) => (
          <span key={`${entry.name}@${entry.version}`} className="flex items-center gap-1">
            <Badge size="sm">{`${entry.name ?? "—"}@${entry.version ?? "—"}`}</Badge>
            {entry.fixed_in_version && (
              <Badge variant="metric" tone="success" label="fixed in" value={entry.fixed_in_version} />
            )}
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * The address that answered, as `ip:port`.
 *
 * OCSF's home for it is the evidence's destination endpoint, which is where an
 * engine that resolved a name writes what it resolved to. A URL alone does not
 * say it: behind a load balancer or a wildcard DNS record, which host served the
 * request is the fact that makes a finding reproducible.
 */
function resolvedAddress(finding: Finding): string | undefined {
  const endpoint = (finding.evidences ?? []).map((entry) => entry.dst_endpoint).find(Boolean);
  if (!endpoint) return undefined;
  return [endpoint.ip || endpoint.hostname, endpoint.port].filter(Boolean).join(":") || undefined;
}

function overviewProperties(
  finding: Finding,
  unmapped: Record<string, unknown>,
): { key: string; value: ReactNode; hidden?: boolean }[] {
  const info = finding.finding_info ?? {};
  const matchedAt = finding.matchedAt;
  // The template path, which nuclei reports and OCSF models as the alternate
  // identifier of the thing that found this.
  const templatePath = info.uid_alt;
  const account = finding.cloud?.account;
  const stamped = finding.time ? new Date(finding.time).toISOString() : undefined;
  const address = resolvedAddress(finding);

  return [
    { key: "Severity", value: severityBadge(severityOf(finding)) },
    {
      key: "Check",
      value: (
        <div className="flex flex-col">
          <Mono>{finding.checkId}</Mono>
          {templatePath && <span className="text-[11px] text-muted-foreground">{templatePath}</span>}
        </div>
      ),
    },
    { key: "Engine", value: <Mono>{finding.engine ?? "—"}</Mono> },
    {
      key: "Status",
      value: <Mono>{finding.status_code}</Mono>,
      hidden: !finding.status_code,
    },
    {
      key: "Detail",
      value: <Mono>{finding.status_detail}</Mono>,
      hidden: !finding.status_detail,
    },
    {
      key: "Verdict",
      value: <Mono>{finding.verdict}</Mono>,
      // Every finding is a failure unless it says otherwise, so the default
      // carries no information worth a row.
      hidden: !finding.verdict || finding.verdict === "fail",
    },
    { key: "Host", value: <Mono>{finding.host || "—"}</Mono> },
    {
      key: "Account",
      value: (
        <Mono>
          {[finding.cloud?.provider, account?.name || account?.uid].filter(Boolean).join(" · ")}
        </Mono>
      ),
      hidden: !finding.cloud?.provider && !account?.uid,
    },
    {
      key: "Region",
      value: <Mono>{finding.cloud?.region}</Mono>,
      hidden: !finding.cloud?.region,
    },
    {
      key: finding.resources && finding.resources.length > 1 ? "Resources" : "Resource",
      value: <ResourceList finding={finding} />,
      hidden: !(finding.resources?.length ?? 0) && !matchedAt,
    },
    {
      key: "Matched at",
      value: <Mono>{matchedAt}</Mono>,
      // Only where it says something the resource does not. For nuclei it is the
      // URL that answered and worth its own row; for a cloud posture scan it is
      // the resource uid, already above.
      hidden: !matchedAt || finding.resources?.some((r) => r.uid === matchedAt) === true,
    },
    {
      key: "Address",
      value: <Mono>{address}</Mono>,
      hidden: !address,
    },
    {
      key: "Reference",
      value: <Mono>{info.src_url}</Mono>,
      // Only when it is not already in the References list above. Engines that
      // report one link report it as both, and printing it twice reads as two
      // sources rather than one.
      hidden: !info.src_url || (finding.remediation?.references ?? []).includes(info.src_url),
    },
    { key: "Tags", value: <Mono>{finding.tags.join(", ")}</Mono>, hidden: !finding.tags.length },
    {
      key: "Timestamp",
      value: <Mono>{stamped}</Mono>,
      hidden: !stamped,
    },
    {
      key: "Scan",
      value: (
        <Mono>
          {finding.scanId} · line {finding.lineNo}
        </Mono>
      ),
    },
    // Whatever the engine reported that the schema has no name for. It is the
    // last section rather than the first because everything above it now has a
    // published name, which is the whole point of the record being OCSF.
    ...Object.entries(unmapped).map(([key, value]) => ({
      key: `unmapped.${key}`,
      value: <Mono>{text(value) ?? JSON.stringify(value)}</Mono>,
    })),
  ];
}

function Overview({ finding }: { finding: Finding }) {
  const info = finding.finding_info ?? {};
  const description = info.desc;
  const impact = finding.risk_details || finding.impact;
  const remediation = finding.remediation?.desc;
  const references = finding.remediation?.references ?? [];
  const unmapped = record(finding.unmapped);
  const error = text(unmapped.error);

  return (
    <div className="flex flex-col gap-3">
      <Classification vulnerabilities={finding.vulnerabilities ?? []} />
      {error && (
        <p role="alert" className="rounded border border-destructive/40 bg-destructive/5 p-2 text-sm text-destructive">
          {String(error)}
        </p>
      )}
      {description && <Prose title="Description" body={description} />}
      {impact && <Prose title="Impact" body={impact} />}
      {remediation && <Prose title="Recommended action" body={remediation} />}
      <AffectedPackages vulnerabilities={finding.vulnerabilities ?? []} />
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
        items={overviewProperties(finding, record(finding.unmapped))}
        renderValue={(_key, value) => value}
        renderLabel={(key) => key.replace(/^unmapped\./, "")}
        density="compact"
        showDensityMenu={false}
      />
    </div>
  );
}

type EvidenceBlock = { title: string; language: string; source: string };

// `request` and `response` are HTTP wire text only for http-family templates. A
// javascript or code template puts its own source in the request and whatever it
// exported in the response, so highlighting either as HTTP misreads it. The
// protocol is nuclei's own fact, which is why it lives in `unmapped`.
const REQUEST_LANGUAGE: Record<string, string> = { javascript: "javascript", code: "bash" };

/**
 * What a finding leaves behind, from the one place every engine now writes it.
 *
 * There used to be three of these — one reading nuclei's request/response/curl
 * columns, one digging InSpec's assertion out of `raw.result`, one digging
 * trivy's code lines out of `raw.Code` or `raw.CauseMetadata` — and an engine
 * the list did not name showed an empty tab however much it had reported.
 * `evidences[]` is the same shape for all four, so this is one function.
 *
 * `data` is OCSF's json_t: the engine's own shape, which the schema has no
 * names for. It renders as JSON rather than being picked apart by key, because
 * picking it apart by key is exactly what this replaced.
 */
function evidenceBlocks({
  entry,
  protocol,
  matchedAt,
}: {
  entry: EvidenceEntry;
  protocol: string;
  // Where the finding says it is. The evidence names the same location for
  // every HTTP engine, and a block repeating it reads as a second fact.
  matchedAt: string;
}): EvidenceBlock[] {
  const language = REQUEST_LANGUAGE[protocol] ?? "http";
  const label = entry.name ? `${entry.name} · ` : "";
  const prose = typeof entry.data === "string";
  const details =
    entry.data === undefined || entry.data === null
      ? undefined
      : prose
        ? (entry.data as string)
        : JSON.stringify(entry.data, null, 2);

  return [
    entry.http_request?.args && {
      title: `${label}Request`,
      language,
      source: entry.http_request.args,
    },
    entry.http_response?.message && {
      title: `${label}Response`,
      language: language === "http" ? "http" : "text",
      source: entry.http_response.message,
    },
    details && {
      // A string payload is the whole of what the entry carries — InSpec's
      // control source is the case — so the entry's own name titles it rather
      // than being suffixed with a word for a wrapper that is not there.
      title: prose ? entry.name || "Details" : `${label}Details`,
      language: prose ? "text" : "json",
      source: details,
    },
    entry.url?.url_string !== matchedAt &&
      entry.url?.url_string && {
        title: `${label}URL`,
        language: "text",
        source: entry.url.url_string,
      },
  ].filter((block): block is EvidenceBlock => Boolean(block));
}

export function FindingDetail({
  finding,
  engine,
  onMute,
}: {
  finding: Finding;
  // The scan engine the run used, which scopes the rule to the engine that
  // reported the finding. Not finding.type, which is the protocol family.
  engine?: string;
  // Optional: this renders wherever a finding does, and not every one of those
  // places can navigate to the rule editor.
  onMute?: (path: string) => void;
}) {
  const protocol = text(record(finding.unmapped).protocol) ?? "";
  const evidence = (finding.evidences ?? []).flatMap((entry) =>
    evidenceBlocks({ entry, protocol, matchedAt: finding.matchedAt }),
  );

  // Engines that match on a parsed document rather than a transaction (dns,
  // ssl, file) carry no evidence at all — an empty Evidence tab would say
  // "look here" about nothing.
  const tabs: TabItem[] = [
    { id: "overview", label: "Overview" },
    ...(evidence.length ? [{ id: "evidence", label: "Evidence", count: evidence.length }] : []),
    { id: "raw", label: "Raw JSON" },
  ];
  const [tab, setTab] = useState("overview");
  const muteOptions = muteScopeOptions(finding, engine);

  return (
    // `w-0 min-w-full` keeps the detail out of the table's width calculation:
    // the cell spans every column, so a wide request body or JSON tree would
    // otherwise stretch the table past its scroll container and shift every
    // column the moment a row is expanded.
    <div className="flex w-0 min-w-full flex-col gap-3 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tabs tabs={tabs} value={tab} onChange={setTab} />
        <span className="flex-1" />
        {/* A menu rather than a button because how much to hide is the actual
            decision: this bucket being public by design and this check being
            noise everywhere are different facts, and only one of them is about
            this finding. Each choice opens the editor on a prefilled draft
            rather than muting on the spot — muting drops findings instead of
            marking them, so what a rule would take is worth seeing first. */}
        {onMute && muteOptions.length > 0 && (
          <DropdownMenu
            variant="outline"
            size="sm"
            label="Mute this finding"
            menuLabel="Mute scope"
            items={muteOptions.map((option) => ({
              label: option.label,
              title: option.title,
              onSelect: () => onMute(option.path),
            }))}
          />
        )}
      </div>
      {tab === "overview" && <Overview finding={finding} />}
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
