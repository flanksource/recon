import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, DataTable } from "@flanksource/clicky-ui";
import { columns } from "./columns";
import { BulkEditBar, type BulkEdit } from "./BulkEditBar";
import { DiscoverDialog } from "./DiscoverDialog";
import { PingDialog } from "./PingDialog";
import { ScanDialog } from "./ScanDialog";
import { selectionQuery, useEntityFilters } from "./filters";
import { useScanStatus } from "./useScanStatus";
import { fetchTargets, saveTargets } from "./api";
import {
  curatedTarget,
  type TableRow,
  type TargetRow,
  type TargetSelector,
} from "./types";

function sameDefinition(left: TargetRow, right: TargetRow): boolean {
  return (
    JSON.stringify(curatedTarget(left)) === JSON.stringify(curatedTarget(right))
  );
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
      if (edit.value === "deactivated")
        return { ...row, class: edit.value, reason: edit.reason };
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
  // Two states, deliberately. `served` is what the database says; `edits` is
  // what the user has changed and not yet saved, keyed by host. Keeping them
  // apart is what makes a reload safe: the server's answer replaces `served`
  // and the edits are re-applied on top, so narrowing a filter or finishing a
  // scan can no longer throw away typing.
  const [served, setServed] = useState<TargetRow[]>([]);
  const [edits, setEdits] = useState<Record<string, TargetRow>>({});
  const [selectedIds, setSelectedIds] = useState<string[]>(
    () => routeParams.get("selected")?.split(",").filter(Boolean) ?? [],
  );
  const [query, setQuery] = useState(() => routeParams.get("q") ?? "");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [discoverOpen, setDiscoverOpen] = useState(false);
  const [scanOpen, setScanOpen] = useState(false);
  const [pingOpen, setPingOpen] = useState(false);

  const { filters, selection, error: filterError } = useEntityFilters("target");

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setServed(
        await fetchTargets(selectionQuery(selection) as TargetSelector),
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [selection]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    const url = new URL(window.location.href);
    if (query) url.searchParams.set("q", query);
    else url.searchParams.delete("q");
    if (selectedIds.length > 0)
      url.searchParams.set("selected", selectedIds.join(","));
    else url.searchParams.delete("selected");
    window.history.replaceState(window.history.state, "", url);
  }, [query, selectedIds]);

  // The rows the table shows: what the server returned, with unsaved edits laid
  // over it. Discovery inserts new unclassified targets directly in the store.
  const rows = useMemo<TargetRow[]>(() => {
    return served.map((row) => edits[row.host] ?? row);
  }, [edits, served]);

  const dirty = Object.keys(edits).length > 0;

  // A finished scan stamps the machine-owned scan section, so pull it back in.
  // Unlike before this needs no dirty guard: an edit lives in `edits` and
  // survives the reload.
  const { status: scan, setStatus: setScan } = useScanStatus(() => void load());

  const tableRows = useMemo<TableRow[]>(
    () =>
      rows.map((r) => ({
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
        dirty: r.host in edits,
      })),
    [edits, rows],
  );

  const applyBulk = useCallback(
    (edit: BulkEdit) => {
      const selected = new Set(selectedIds);
      const current = new Map(rows.map((row) => [row.host, row]));
      const stored = new Map(served.map((row) => [row.host, row]));
      setEdits((prev) => {
        const next = { ...prev };
        for (const host of selected) {
          const row = current.get(host);
          if (!row) continue;
          const edited = applyEdit(row, edit);
          // An edit that lands back on what the database already has is not a
          // change, and leaving it in would keep claiming unsaved work.
          const saved = stored.get(host);
          if (saved && sameDefinition(edited, saved)) delete next[host];
          else next[host] = edited;
        }
        return next;
      });
    },
    [rows, selectedIds, served],
  );

  const save = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await saveTargets(Object.values(edits));
      setEdits({});
      setServed(
        await fetchTargets(selectionQuery(selection) as TargetSelector),
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }, [edits, selection]);

  const tagVocabulary = useMemo(() => {
    const tags = new Set<string>();
    rows.forEach((r) => r.tags.forEach((t) => tags.add(t)));
    return [...tags].sort();
  }, [rows]);

  const selectedTags = useMemo(() => {
    const sel = new Set(selectedIds);
    const tags = new Set<string>();
    rows.forEach((r) => sel.has(r.host) && r.tags.forEach((t) => tags.add(t)));
    return [...tags].sort();
  }, [rows, selectedIds]);

  const scannedCount = tableRows.filter((r) => r.last_scan).length;
  const savedHosts = useMemo(() => served.map((r) => r.host), [served]);

  const scanActive = scan?.phase === "queued" || scan?.phase === "running";
  const scanLabel = selectedIds.length
    ? `${scanActive ? "Queue" : "Scan"} ${selectedIds.length} selected`
    : scanActive
      ? "Queue scan"
      : "Scan now";

  return (
    <div className="flex h-full flex-col bg-background text-foreground">
      <header className="flex items-center gap-3 border-b border-border px-4 py-3">
        <h1 className="text-lg font-semibold">Target Inventory</h1>
        <span className="text-sm text-muted-foreground">
          {rows.length} targets · {scannedCount} scanned ·{" "}
          {tagVocabulary.length} tags
        </span>
        <span className="flex-1" />
        {(error ?? filterError) && (
          <span className="text-sm text-destructive" role="alert">
            {error ?? filterError}
          </span>
        )}
        {dirty && (
          <span className="text-sm text-amber-600 dark:text-amber-400">
            Unsaved changes
          </span>
        )}
        <Button
          variant="outline"
          size="sm"
          onClick={() => setDiscoverOpen(true)}
          disabled={busy}
        >
          Discover targets
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setPingOpen(true)}
          disabled={busy}
        >
          Ping hosts
        </Button>
        <Button
          variant={scanActive ? "default" : "outline"}
          size="sm"
          onClick={() => setScanOpen(true)}
        >
          {scanLabel}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void load()}
          disabled={busy}
        >
          Reload
        </Button>
        <Button
          size="sm"
          onClick={() => void save()}
          disabled={busy || !dirty}
          loading={busy}
        >
          Save inventory
        </Button>
      </header>

      <DiscoverDialog
        open={discoverOpen}
        onClose={() => setDiscoverOpen(false)}
        onDiscovered={() => void load()}
      />

      <PingDialog
        open={pingOpen}
        onClose={() => setPingOpen(false)}
        rows={tableRows}
        selectedHosts={selectedIds}
        onProbed={() => void load()}
      />

      {scanOpen && (
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
      )}

      <main className="min-h-0 flex-1 p-3">
        <DataTable<TableRow>
          data={tableRows}
          columns={columns}
          getRowId={(row) => row.host}
          getRowHref={(row) => `/inventory/${encodeURIComponent(row.host)}`}
          onRowClick={(row) => onOpenTarget(row.host)}
          // The controls come from the entity's own filter declaration and the
          // database answers them, so these rows arrived narrowed. DataTable
          // never applies caller-supplied filters itself, which is what lets
          // the search box keep narrowing the result further in the browser.
          externalFilters={filters}
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
              tagVocabulary={tagVocabulary}
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
