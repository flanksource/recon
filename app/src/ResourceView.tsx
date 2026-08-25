import { useEffect, useMemo, useState } from "react";
import { Button, Panel } from "@flanksource/clicky-ui/components";
import { Badge, DataTable, KeyValueList } from "@flanksource/clicky-ui/data";
import type { DataTableColumn } from "@flanksource/clicky-ui/data";
import { FindingDetail } from "./FindingDetail";
import { severityBadge, SEVERITY_RANK } from "./scanColumns";
import { typeTail } from "./resourceColumns";
import {
  fetchResource,
  fetchResourceFindings,
  type Resource,
} from "./api-resources";
import type { Finding, Severity } from "./types";

/** One resource, and every check that has reported a verdict about it. */
export function ResourceView({
  id,
  onBack,
  onMuteFinding,
}: {
  id: string;
  onBack: () => void;
  onMuteFinding?: (path: string) => void;
}) {
  const [resource, setResource] = useState<Resource | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setBusy(true);
    setError(null);
    Promise.all([fetchResource(id), fetchResourceFindings(id)])
      .then(([found, evidence]) => {
        if (cancelled) return;
        setResource(found);
        setFindings(evidence);
      })
      .catch((e: Error) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [id]);

  const compliance = useMemo(() => frameworkRollup(findings), [findings]);

  if (error) {
    return (
      <div className="p-6">
        <p className="text-sm text-destructive">{error}</p>
        <Button className="mt-3" size="sm" variant="outline" onClick={onBack}>
          Back to resources
        </Button>
      </div>
    );
  }
  if (busy || !resource) {
    return <div className="p-6 text-sm text-muted-foreground">Loading…</div>;
  }

  const display = (value: unknown) =>
    value === undefined || value === "" ? "—" : String(value);

  return (
    <div className="flex h-full min-h-0 flex-col gap-4 overflow-auto p-4">
      <div className="flex items-center gap-3">
        <Button size="sm" variant="outline" onClick={onBack}>
          Back
        </Button>
        <h1 className="truncate text-lg font-semibold">
          {resource.name || resource.uid}
        </h1>
        {/* "Last seen", never "deleted". Whether it was decommissioned or
            whether an API call failed is a judgement recon cannot make, so it
            reports the observation rather than a conclusion. */}
        {resource.state === "absent" && (
          <span title="a covering run no longer sees it">
            <Badge tone="warning">last seen {resource.lastSeen}</Badge>
          </span>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Identity">
          <KeyValueList
            items={[
              { key: "uid", label: "UID", value: resource.uid },
              { key: "name", label: "Name", value: display(resource.name) },
              {
                key: "type",
                label: "Type",
                value: (
                  <span title={resource.type}>{typeTail(resource.type) || "—"}</span>
                ),
              },
              { key: "kind", label: "Kind", value: resource.kind },
              { key: "provider", label: "Provider", value: resource.provider },
              { key: "scope", label: "Account", value: display(resource.scope) },
              { key: "service", label: "Service", value: display(resource.service) },
              { key: "region", label: "Region", value: display(resource.region) },
              { key: "target", label: "Target", value: display(resource.targetId) },
              { key: "engines", label: "Engines", value: display(resource.engines?.join(", ")) },
              { key: "firstSeen", label: "First seen", value: display(resource.firstSeen) },
              { key: "lastSeen", label: "Last seen", value: display(resource.lastSeen) },
              // The identity Mission Control's catalog would hold the same
              // thing under, empty wherever recon cannot say.
              { key: "configType", label: "Config type", value: display(resource.configType) },
              {
                key: "externalIds",
                label: "External IDs",
                value: display(resource.externalIds?.join(", ")),
              },
            ]}
          />
        </Panel>

        <Panel title="Compliance">
          <KeyValueList
            items={[
              {
                key: "open",
                label: "Open findings",
                value:
                  resource.findings === 0 ? (
                    <span className="text-sm text-muted-foreground">none</span>
                  ) : (
                    <span className="inline-flex gap-1">
                      {(Object.keys(resource.severities ?? {}) as Severity[])
                        .sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b])
                        .map((severity) => (
                          <span key={severity} className="inline-flex items-center gap-0.5">
                            {severityBadge(severity)}
                            <span className="text-xs tabular-nums">
                              {resource.severities?.[severity]}
                            </span>
                          </span>
                        ))}
                    </span>
                  ),
              },
              ...compliance.map(([framework, count]) => ({
                key: framework,
                label: framework,
                value: `${count} failing control${count === 1 ? "" : "s"}`,
              })),
              { key: "tags", label: "Tags", value: display(resource.tags?.join(", ")) },
              {
                key: "labels",
                label: "Labels",
                value: display(
                  Object.entries(resource.labels ?? {})
                    .map(([k, v]) => `${k}=${v}`)
                    .join(", "),
                ),
              },
            ]}
          />
        </Panel>
      </div>

      <Panel title={`Findings (${findings.length})`}>
        {findings.length === 0 ? (
          <p className="p-3 text-sm text-muted-foreground">
            Nothing is currently open against this resource.
          </p>
        ) : (
          <DataTable<Finding>
            data={findings}
            columns={findingColumnsForResource}
            getRowId={(row) => `${row.scanId}#${row.lineNo}`}
            detailStyle="row"
            // The existing detail, so the mute menu stays reachable from the
            // resource page rather than only from the run it came from.
            renderExpandedRow={(row) => (
              <FindingDetail finding={row} onMute={onMuteFinding} />
            )}
          />
        )}
      </Panel>

      {resource.metadata && Object.keys(resource.metadata).length > 0 && (
        <Panel title="Provider record">
          <pre className="max-h-96 overflow-auto p-3 text-xs">
            {JSON.stringify(resource.metadata, null, 2)}
          </pre>
        </Panel>
      )}
    </div>
  );
}

const findingColumnsForResource: DataTableColumn<Finding>[] = [
  {
    key: "severity",
    label: "Severity",
    render: (value) => severityBadge(value as Severity),
    sortValue: (_value, row) => SEVERITY_RANK[row.severity as Severity],
  },
  { key: "templateId", label: "Check" },
  { key: "name", label: "Title" },
  { key: "timestamp", label: "Reported" },
];

/**
 * Failing controls per compliance framework.
 *
 * Read from the `compliance:CIS-5.0:1.13` tags the checks already carry rather
 * than from a framework catalogue recon would have to maintain: the tags are
 * what the engine actually asserted, and a roll-up derived from anything else
 * would disagree with the findings underneath it.
 */
export function frameworkRollup(findings: Finding[]): [string, number][] {
  const counts = new Map<string, number>();
  for (const finding of findings) {
    const frameworks = new Set<string>();
    for (const tag of finding.tags ?? []) {
      if (!tag.startsWith("compliance:")) continue;
      // compliance:CIS-5.0:1.13 → CIS-5.0. Split on the second colon only: a
      // control id contains dots but the framework is the middle segment.
      const parts = tag.split(":");
      if (parts.length >= 2 && parts[1]) frameworks.add(parts[1]);
    }
    // Counted once per finding per framework, so a control tagged with three
    // sections of the same benchmark is one failing control, not three.
    for (const framework of frameworks) {
      counts.set(framework, (counts.get(framework) ?? 0) + 1);
    }
  }
  return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b));
}
