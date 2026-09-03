import { useEffect, useState } from "react";
import { Button, Panel } from "@flanksource/clicky-ui/components";
import { Badge, DataTable, KeyValueList } from "@flanksource/clicky-ui/data";
import type { DataTableColumn } from "@flanksource/clicky-ui/data";
import { FindingDetail } from "./FindingDetail";
import { severityBadge, SEVERITY_RANK } from "./scanColumns";
import { typeTail } from "./resourceColumns";
import {
  fetchResource,
  fetchResourceConfig,
  fetchResourceFindings,
  removeResourceConfig,
  type LinkedConfig,
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
  const [linkedConfig, setLinkedConfig] = useState<LinkedConfig | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [unlinking, setUnlinking] = useState(false);
  const [unlinkError, setUnlinkError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setBusy(true);
    setError(null);
    Promise.all([
      fetchResource(id),
      fetchResourceConfig(id),
      fetchResourceFindings(id),
    ])
      .then(([found, config, evidence]) => {
        if (cancelled) return;
        setResource(found);
        setLinkedConfig(config);
        setFindings(evidence);
      })
      .catch((e: Error) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [id]);

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

  const unlinkConfig = async () => {
    if (!window.confirm("Remove the Mission Control config link from this resource?")) return;
    setUnlinking(true);
    setUnlinkError(null);
    try {
      await removeResourceConfig(id);
      setLinkedConfig(null);
    } catch (e) {
      setUnlinkError((e as Error).message);
    } finally {
      setUnlinking(false);
    }
  };

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

      <div>
        {unlinkError && (
          <div className="mb-3 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {unlinkError}
          </div>
        )}
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
              {
                key: "configName",
                label: "Config name",
                value: linkedConfig ? (
                  <span className="inline-flex items-center gap-2">
                    <a
                      href={linkedConfig.url}
                      target="_blank"
                      rel="noreferrer"
                      className="font-medium text-primary hover:underline"
                    >
                      {linkedConfig.name || linkedConfig.id}
                    </a>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={unlinking}
                      onClick={() => void unlinkConfig()}
                    >
                      {unlinking ? "Removing…" : "Remove link"}
                    </Button>
                  </span>
                ) : "—",
              },
              { key: "configType", label: "Config type", value: display(linkedConfig?.type) },
              { key: "configId", label: "Config ID", value: display(linkedConfig?.id) },
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
