import { useCallback, useEffect, useState } from "react";
import {
  Button,
  Modal,
} from "@flanksource/clicky-ui/components";
import {
  DataTable,
  type DataTableColumn,
} from "@flanksource/clicky-ui/data";
import { fetchLatestDiscovery, runDiscovery } from "./api";
import {
  DiscoveryProfiles,
  describeSelection,
  discoveryRunFields,
  useDiscoveryProfiles,
} from "./DiscoveryProfiles";
import type { DiscoveredHost, Discover } from "./types";

function relativeTime(iso: string | null): string {
  if (!iso) return "never";
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) return iso;
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

function values(input: string): string[] | undefined {
  const parsed = [
    ...new Set(
      input
        .split(/[\s,]+/)
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  ];
  return parsed.length > 0 ? parsed : undefined;
}

const discoveredColumns: DataTableColumn<DiscoveredHost>[] = [
  {
    key: "host",
    label: "Host",
    grow: true,
    sortable: true,
    render: (value) => (
      <a
        href={`https://${String(value)}`}
        target="_blank"
        rel="noreferrer"
        className="font-medium hover:underline"
      >
        {String(value)}
      </a>
    ),
  },
  {
    key: "engines",
    label: "Observed by",
    kind: "tags",
    tags: { maxVisible: 4 },
  },
  {
    key: "live",
    label: "Live",
    shrink: true,
    align: "center",
    render: (value) => (value ? "yes" : "no"),
  },
];

type Props = {
  open: boolean;
  onClose: () => void;
  onDiscovered: () => void;
};

export function DiscoverDialog({ open, onClose, onDiscovered }: Props) {
  const [hosts, setHosts] = useState<DiscoveredHost[]>([]);
  const [running, setRunning] = useState(false);
  const [ranAt, setRanAt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [domains, setDomains] = useState("");
  const [hostInput, setHostInput] = useState("");
  const [cidrs, setCIDRs] = useState("");
  const [editingProfiles, setEditingProfiles] = useState(false);
  const profiles = useDiscoveryProfiles(open);

  const applyResult = useCallback((result: Discover) => {
    setHosts(result.hosts);
    setRanAt(result.ranAt);
  }, []);

  const discover = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      applyResult(
        await runDiscovery({
          domain: values(domains),
          host: values(hostInput),
          cidr: values(cidrs),
          profile: profiles.refs,
          ...discoveryRunFields(profiles),
        }),
      );
      setEditingProfiles(false);
      onDiscovered();
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setRunning(false);
    }
  }, [applyResult, cidrs, domains, hostInput, onDiscovered, profiles]);

  const loadLatest = useCallback(async () => {
    try {
      const latest = await fetchLatestDiscovery();
      if (latest) applyResult(latest);
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setLoaded(true);
    }
  }, [applyResult]);

  useEffect(() => {
    if (open && !loaded && !running) void loadLatest();
  }, [loadLatest, loaded, open, running]);

  useEffect(() => {
    if (!open) setLoaded(false);
  }, [open]);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Discover targets"
      size="xl"
      className="h-[calc(100dvh-4rem)]"
      scrollBody={false}
    >
      <div className="flex min-h-0 flex-1 flex-col gap-3">
        <div className="grid shrink-0 grid-cols-1 gap-3 rounded-md border border-border bg-muted/30 p-3 md:grid-cols-4">
          <label className="flex flex-col gap-1 text-xs">
            Domains
            <input
              value={domains}
              onChange={(event) => setDomains(event.target.value)}
              placeholder="example.com"
              className="h-8 rounded-md border border-input bg-background px-2 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Hosts
            <input
              value={hostInput}
              onChange={(event) => setHostInput(event.target.value)}
              placeholder="api.example.com, 192.0.2.10"
              className="h-8 rounded-md border border-input bg-background px-2 text-sm"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            CIDRs
            <input
              value={cidrs}
              onChange={(event) => setCIDRs(event.target.value)}
              placeholder="192.0.2.0/24"
              className="h-8 rounded-md border border-input bg-background px-2 text-sm"
            />
          </label>
          <span className="flex flex-col gap-1 text-xs">
            Profiles
            <Button
              size="sm"
              variant="outline"
              aria-expanded={editingProfiles}
              disabled={running || !profiles.loaded}
              onClick={() => setEditingProfiles((current) => !current)}
            >
              {editingProfiles ? "Done editing" : "Edit profiles"}
            </Button>
          </span>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-3 text-sm">
          <Button
            size="sm"
            onClick={() => void discover()}
            loading={running}
            disabled={running || !profiles.loaded}
          >
            Run discovery
          </Button>
          <span className="flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
            {describeSelection(profiles).map(({ engine, name }) => (
              <span key={engine} className="rounded bg-muted px-1.5 py-0.5">
                {engine} · {name}
              </span>
            ))}
            {profiles.edited && (
              <span className="text-amber-600 dark:text-amber-400">
                reconfigured for this sweep only
              </span>
            )}
          </span>
          {running && (
            <span className="text-muted-foreground">
              Enumerating and probing targets…
            </span>
          )}
          {!running && ranAt && (
            <span className="text-muted-foreground">
              {hosts.length} hosts auto-inventoried · last discovered{" "}
              {relativeTime(ranAt)}
            </span>
          )}
          {!running && !ranAt && loaded && (
            <span className="text-muted-foreground">
              No previous discovery. Empty input uses configured zones.
            </span>
          )}
          {(error ?? profiles.error) && (
            <span className="text-destructive">{error ?? profiles.error}</span>
          )}
        </div>

        {editingProfiles && (
          <DiscoveryProfiles state={profiles} disabled={running} />
        )}

        <div
          className={`flex min-h-0 flex-col overflow-hidden rounded-md border border-border ${
            editingProfiles ? "hidden" : "flex-1"
          }`}
        >
          <DataTable<DiscoveredHost>
            className="min-h-0 flex-1"
            data={hosts}
            columns={discoveredColumns}
            getRowId={(row) => row.host}
            autoFilter
            showGlobalFilter
            globalFilterPlaceholder="Search discovered hosts…"
            defaultSort={{ key: "host" }}
            loading={running}
            loadingMessage="Discovering targets…"
            emptyMessage="No hosts found."
          />
        </div>
      </div>
    </Modal>
  );
}
