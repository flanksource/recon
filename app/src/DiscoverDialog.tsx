import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Button,
  DataTable,
  Modal,
  MultiSelect,
  Select,
  type DataTableColumn,
} from "@flanksource/clicky-ui";
import { HttpStatusBadge } from "./columns";
import { fetchDiscoveryCache, runDiscovery } from "./api";
import {
  CLASS_ORDER,
  PROFILES,
  type DiscoveredHost,
  type DiscoverResult,
  type TargetClass,
  type TargetRow,
} from "./types";

function relativeTime(iso: string | null): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(s)) return iso;
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

const discoveredColumns: DataTableColumn<DiscoveredHost>[] = [
  {
    key: "host",
    label: "Host",
    grow: true,
    sortable: true,
    render: (value, row) => (
      <div className="flex items-center gap-2">
        <a href={`https://${String(value)}`} target="_blank" rel="noreferrer" className="font-medium hover:underline">
          {String(value)}
        </a>
        {row.isKnown ? (
          <span className="rounded bg-neutral-500/15 px-1.5 py-0.5 text-xs text-muted-foreground">
            known
          </span>
        ) : (
          <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-xs text-emerald-600 dark:text-emerald-300">
            new
          </span>
        )}
      </div>
    ),
  },
  {
    key: "status",
    label: "Status",
    shrink: true,
    align: "center",
    sortable: true,
    render: (value) => <HttpStatusBadge value={value} />,
  },
  { key: "responseTime", label: "Response", shrink: true },
  { key: "openPorts", label: "Open ports", kind: "tags", tags: { maxVisible: 3 } },
  { key: "knownPaths", label: "Known paths", kind: "tags", tags: { maxVisible: 2 } },
  { key: "loginMethods", label: "Login methods", kind: "tags", tags: { maxVisible: 2 } },
  { key: "title", label: "Title", grow: true },
  { key: "tech", label: "Tech", kind: "tags", tags: { maxVisible: 3 } },
];

type Props = {
  open: boolean;
  onClose: () => void;
  tagVocabulary: string[];
  onAdd: (rows: TargetRow[]) => number;
};

export function DiscoverDialog({ open, onClose, tagVocabulary, onAdd }: Props) {
  const [hosts, setHosts] = useState<DiscoveredHost[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [ranAt, setRanAt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [cls, setCls] = useState<TargetClass>("non-prod");
  const [profiles, setProfiles] = useState<string[]>(["safe"]);
  const [tags, setTags] = useState<string[]>([]);
  const [tagInput, setTagInput] = useState("");

  const [loaded, setLoaded] = useState(false);

  const applyResult = (res: DiscoverResult) => {
    setHosts(res.hosts);
    setRanAt(res.ranAt);
    // Pre-select new + live hosts.
    setSelectedIds(res.hosts.filter((h) => !h.isKnown && h.live).map((h) => h.host));
  };

  // Refresh: re-run static, DNS, subfinder, Naabu, and httpx discovery and re-cache.
  const discover = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      applyResult(await runDiscovery());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  }, []);

  // On open, load the cached prior results instantly (cheap GET). Never auto-runs the
  // expensive refresh — the user triggers that explicitly.
  const loadCache = useCallback(async () => {
    try {
      applyResult(await fetchDiscoveryCache());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (open && !loaded && !running) void loadCache();
  }, [open, loaded, running, loadCache]);

  // Re-fetch the cache next open so hosts added since (now known) reflect correctly.
  useEffect(() => {
    if (!open) setLoaded(false);
  }, [open]);

  const newCount = useMemo(() => hosts.filter((h) => !h.isKnown).length, [hosts]);

  const addTag = () => {
    const t = tagInput.trim();
    if (t && !tags.includes(t)) setTags([...tags, t]);
    setTagInput("");
  };

  const commitAdd = () => {
    const chosen = new Set(selectedIds);
    const rows: TargetRow[] = hosts
      .filter((h) => chosen.has(h.host) && !h.isKnown)
      .map((h) => ({
        $schema: "../target.schema.json",
        version: 1,
        class: cls,
        host: h.host,
        source: "discovered",
        profiles: [...profiles],
        tags: [...tags],
        notes: h.title ? `Discovered — ${h.title}` : "Discovered via static/DNS/httpx.",
      }));
    const added = onAdd(rows);
    if (added > 0) onClose();
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Discover subdomains"
      size="xl"
      // The panel is content-sized by default (max-height only); pin a height and
      // hand scrolling to the table so the row list fills the dialog.
      className="h-[calc(100dvh-4rem)]"
      scrollBody={false}
    >
      <div className="flex min-h-0 flex-1 flex-col gap-3">
        <div className="flex shrink-0 items-center gap-3 text-sm">
          <Button size="sm" onClick={() => void discover()} loading={running} disabled={running}>
            {ranAt ? "Refresh discovery" : "Run discovery"}
          </Button>
          {running && (
            <span className="text-muted-foreground">
              Resolving NS/MX records, enumerating subdomains, scanning ports with Naabu, and probing with httpx —
              this can take a minute…
            </span>
          )}
          {!running && ranAt && (
            <span className="text-muted-foreground">
              {hosts.length} hosts · {newCount} new · {selectedIds.length} selected ·{" "}
              <span title={ranAt}>last discovered {relativeTime(ranAt)}</span>
            </span>
          )}
          {!running && !ranAt && loaded && (
            <span className="text-muted-foreground">
              No cached results — run discovery to enumerate subdomains.
            </span>
          )}
          {error && <span className="text-destructive">{error}</span>}
        </div>

        <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-md border border-border">
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
            loadingMessage="Discovering subdomains…"
            emptyMessage="No hosts found. Run discovery."
            rowSelection={{
              selectedRowIds: selectedIds,
              onSelectionChange: (ids) => setSelectedIds(ids),
              isRowSelectable: (row) => !row.isKnown,
            }}
          />
        </div>

        <div className="flex shrink-0 flex-wrap items-end gap-3 rounded-md border border-border bg-muted/30 p-3">
          <span className="text-sm font-medium">Classify selected as:</span>
          <label className="flex flex-col gap-1 text-xs">
            Class
            <Select
              className="w-36"
              value={cls}
              options={CLASS_ORDER.filter((value) => value !== "deactivated").map((value) => ({
                value,
                label: value,
              }))}
              onChange={(e) => setCls(e.target.value as TargetClass)}
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Profiles
            <MultiSelect
              className="w-40"
              placeholder="profiles"
              value={profiles}
              options={PROFILES.map((p) => ({ value: p, label: p }))}
              onChange={setProfiles}
            />
          </label>
          <label className="flex flex-col gap-1 text-xs">
            Tags
            <div className="flex items-center gap-1">
              <input
                list="discover-tag-vocab"
                value={tagInput}
                onChange={(e) => setTagInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addTag()}
                placeholder="tag…"
                className="h-8 w-36 rounded-md border border-input bg-background px-2 text-sm"
              />
              <datalist id="discover-tag-vocab">
                {tagVocabulary.map((t) => (
                  <option key={t} value={t} />
                ))}
              </datalist>
              <Button size="sm" variant="outline" onClick={addTag}>
                +
              </Button>
            </div>
          </label>
          {tags.length > 0 && (
            <span className="flex flex-wrap items-center gap-1 pb-1">
              {tags.map((t) => (
                <button
                  key={t}
                  onClick={() => setTags(tags.filter((x) => x !== t))}
                  className="rounded bg-muted px-1.5 py-0.5 text-xs hover:line-through"
                  title="Remove tag"
                >
                  {t} ✕
                </button>
              ))}
            </span>
          )}
          <span className="flex-1" />
          <Button
            onClick={commitAdd}
            disabled={selectedIds.length === 0}
          >
            Add {selectedIds.length} to inventory
          </Button>
        </div>
      </div>
    </Modal>
  );
}
