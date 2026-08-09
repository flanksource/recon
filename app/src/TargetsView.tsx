import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, DataTable } from "@flanksource/clicky-ui";
import { columns } from "./columns";
import { BulkEditBar, type BulkEdit } from "./BulkEditBar";
import { DiscoverDialog } from "./DiscoverDialog";
import { ScanDialog } from "./ScanDialog";
import { useScanStatus } from "./useScanStatus";
import { fetchInventory, saveTargets } from "./api";
import { curatedTarget, type Inventory, type TableRow, type TargetRow } from "./types";

function sameDefinition(left: TargetRow, right: TargetRow): boolean {
  return JSON.stringify(curatedTarget(left)) === JSON.stringify(curatedTarget(right));
}

function applyEdit(row: TargetRow, edit: BulkEdit): TargetRow {
  switch (edit.op) {
    case "add-tag":
      return row.tags.includes(edit.tag)
        ? row
        : { ...row, tags: [...row.tags, edit.tag].sort() };
    case "remove-tag":
      return { ...row, tags: row.tags.filter((t) => t !== edit.tag) };
    case "set-class":
      if (edit.value === "deactivated") return { ...row, class: edit.value, reason: edit.reason };
      const { reason: _reason, ...active } = row;
      return { ...active, class: edit.value };
    case "set-profiles":
      return { ...row, profiles: [...edit.value] };
  }
}

export function InventoryView({
  onOpenScan,
  onOpenTarget,
}: {
  onOpenScan: (file: string) => void;
  onOpenTarget: (host: string) => void;
}) {
  const routeParams = new URLSearchParams(window.location.search);
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [rows, setRows] = useState<TargetRow[]>([]);
  const [original, setOriginal] = useState<TargetRow[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>(() =>
    routeParams.get("selected")?.split(",").filter(Boolean) ?? [],
  );
  const [query, setQuery] = useState(() => routeParams.get("q") ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [discoverOpen, setDiscoverOpen] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);

  // Merge newly classified discovered hosts into the editable inventory. Skips any
  // host already present. Returns how many were actually added.
  const addDiscovered = useCallback(
    (incoming: TargetRow[]): number => {
      let added = 0;
      setRows((prev) => {
        const existing = new Set(prev.map((r) => r.host));
        const fresh = incoming.filter((r) => !existing.has(r.host));
        added = fresh.length;
        return fresh.length ? [...prev, ...fresh] : prev;
      });
      return added;
    },
    [],
  );

  const load = useCallback(async ({ keepSelection = false } = {}) => {
    setBusy(true);
    setError(null);
    try {
      const inv = await fetchInventory();
      setInventory(inv);
      setRows(inv.rows);
      setOriginal(inv.rows);
      if (!keepSelection) setSelectedIds([]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (query) url.searchParams.set("q", query);
    else url.searchParams.delete("q");
    if (selectedIds.length > 0) url.searchParams.set("selected", selectedIds.join(","));
    else url.searchParams.delete("selected");
    window.history.replaceState(window.history.state, "", url);
  }, [query, selectedIds]);

  const dirty = useMemo(
    () =>
      rows.length !== original.length ||
      rows.some((row) => {
        const previous = original.find((target) => target.host === row.host);
        return !previous || !sameDefinition(row, previous);
      }),
    [rows, original],
  );

  // A finished scan stamps the machine-owned scan section — pull it back in so
  // the table reflects it, unless the user has edits that a reload would discard.
  // Keep the selection: it is what the scan ran against, and the dialog's scope reads
  // from it.
  const { status: scan, setStatus: setScan } = useScanStatus(() => {
    if (!dirty) void load({ keepSelection: true });
  });

  const tableRows = useMemo<TableRow[]>(
    () =>
      rows.map((r) => {
        const orig = original.find((o) => o.host === r.host);
        const rowDirty = !orig || !sameDefinition(r, orig);
        return {
          ...r,
          first_observed: r.observed?.first_observed,
          last_seen: r.observed?.last_seen,
          last_scan: r.scan?.last_scan,
          last_status: r.http?.status_code,
          response_time: r.http?.response_time,
          open_ports: r.network?.open_ports?.map(String),
          known_paths: r.http?.known_paths,
          login_methods: r.http?.login_methods,
          findings: r.scan?.last_findings,
          dirty: rowDirty,
        };
      }),
    [rows, original],
  );

  const applyBulk = useCallback(
    (edit: BulkEdit) => {
      const selected = new Set(selectedIds);
      setRows((prev) =>
        prev.map((r) => (selected.has(r.host) ? applyEdit(r, edit) : r)),
      );
    },
    [selectedIds],
  );

  const save = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const changed = rows.filter((row) => {
        const previous = original.find((target) => target.host === row.host);
        return !previous || !sameDefinition(row, previous);
      });
      const inv = await saveTargets(changed);
      setInventory(inv);
      setRows(inv.rows);
      setOriginal(inv.rows);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [original, rows]);

  const selectedTags = useMemo(() => {
    const sel = new Set(selectedIds);
    const tags = new Set<string>();
    rows.forEach((r) => sel.has(r.host) && r.tags.forEach((t) => tags.add(t)));
    return [...tags].sort();
  }, [rows, selectedIds]);

  const scannedCount = tableRows.filter((r) => r.last_scan).length;
  const savedHosts = useMemo(() => original.map((r) => r.host), [original]);

  const scanRunning = scan?.phase === "running";
  const scanLabel = scanRunning
    ? `Scanning ${scan?.stats?.percent ?? 0}%`
    : selectedIds.length
      ? `Scan ${selectedIds.length} selected`
      : "Scan now";

  return (
    <div className="flex h-full flex-col bg-background text-foreground">
      <header className="flex items-center gap-3 border-b border-border px-4 py-3">
        <h1 className="text-lg font-semibold">Target Inventory</h1>
        <span className="text-sm text-muted-foreground">
          {rows.length} targets · {scannedCount} scanned ·{" "}
          {inventory?.tagVocabulary.length ?? 0} tags
        </span>
        <span className="flex-1" />
        {error && (
          <span className="text-sm text-destructive" role="alert">
            {error}
          </span>
        )}
        {dirty && (
          <span className="text-sm text-amber-600 dark:text-amber-400">
            Unsaved changes
          </span>
        )}
        <Button variant="outline" size="sm" onClick={() => setDiscoverOpen(true)} disabled={busy}>
          Discover subdomains
        </Button>
        <Button
          variant={scanRunning ? "default" : "outline"}
          size="sm"
          onClick={() => setScanOpen(true)}
          loading={scanRunning}
        >
          {scanLabel}
        </Button>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={busy}>
          Reload
        </Button>
        <Button size="sm" onClick={() => void save()} disabled={busy || !dirty} loading={busy}>
          Save inventory
        </Button>
      </header>

      <DiscoverDialog
        open={discoverOpen}
        onClose={() => setDiscoverOpen(false)}
        tagVocabulary={inventory?.tagVocabulary ?? []}
        onAdd={addDiscovered}
      />

      <ScanDialog
        open={scanOpen}
        onClose={() => setScanOpen(false)}
        rows={rows}
        savedHosts={savedHosts}
        selectedHosts={selectedIds}
        status={scan}
        onStatus={setScan}
        onOpenScan={(file) => {
          setScanOpen(false);
          onOpenScan(file);
        }}
      />

      <main className="min-h-0 flex-1 p-3">
        <DataTable<TableRow>
          data={tableRows}
          columns={columns}
          getRowId={(row) => row.host}
          getRowHref={(row) => `/inventory/${encodeURIComponent(row.host)}`}
          onRowClick={(row) => onOpenTarget(row.host)}
          autoFilter
          showGlobalFilter
          globalFilter={query}
          onGlobalFilterChange={setQuery}
          globalFilterPlaceholder="Search hosts, tags, apps…"
          defaultSort={{ key: "class" }}
          hideableColumns
          persistColumnVisibility
          columnVisibilityStorageKey="nuclei-inventory-columns"
          resizableColumns
          getRowClassName={(row) =>
            (row as TableRow).dirty ? "bg-amber-500/5" : undefined
          }
          emptyMessage="No targets match the current filters."
          rowSelection={{
            selectedRowIds: selectedIds,
            onSelectionChange: (ids) => setSelectedIds(ids),
          }}
          selectionActions={({ selectedRowIds, clearSelection }) => (
            <BulkEditBar
              count={selectedRowIds.length}
              tagVocabulary={inventory?.tagVocabulary ?? []}
              selectedTags={selectedTags}
              onApply={applyBulk}
              onClear={clearSelection}
            />
          )}
        />
      </main>
    </div>
  );
}
