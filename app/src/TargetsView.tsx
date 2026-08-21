import { useCallback, useEffect, useMemo, useState } from "react";
import { AppShell, Button } from "@flanksource/clicky-ui/components";
import { DataTable } from "@flanksource/clicky-ui/data";
import { columns } from "./columns";
import { BulkEditBar, type BulkEdit } from "./BulkEditBar";
import { AddTargetDialog } from "./AddTargetDialog";
import { DiscoverDialog } from "./DiscoverDialog";
import { PingDialog } from "./PingDialog";
import { ScanDialog } from "./ScanDialog";
import { selectionQuery, useEntityFilters } from "./filters";
import { useScanStatus } from "./useScanStatus";
import { fetchTargets, saveTargets } from "./api";
import {
  curatedTarget,
  targetHost,
  targetId,
  targetKind,
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
  onOpenTarget: (id: string) => void;
}) {
  const routeParams = new URLSearchParams(window.location.search);
  // Two states, deliberately. `served` is what the database says; `edits` is
  // what the user has changed and not yet saved, keyed by stable target id. Keeping them
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
  const [addOpen, setAddOpen] = useState(false);

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

  // Refreshes the rows a probe has just finished, rather than reloading the
  // estate for each batch of hosts a running sweep reports.
  //
  // Refetched rather than patched from the probe result: the server merges a
  // probe into a target — clearing a stale error, stamping last_seen, setting
  // the address, leaving technology and TLS as discovery found them — and
  // reimplementing that merge here is exactly the drift that keeping one prober
  // in the codebase exists to prevent. `edits` is laid back over the top by the
  // `rows` memo, so unsaved typing survives.
  const refreshHosts = useCallback(async (hosts: string[]) => {
    if (hosts.length === 0) return;
    try {
      const refreshed = await fetchTargets({ hosts: hosts.join(",") });
      const byHost = new Map(refreshed.map((row) => [targetHost(row), row]));
      setServed((current) =>
        current.map((row) =>
          targetKind(row) === "host" ? (byHost.get(targetHost(row)) ?? row) : row,
        ),
      );
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

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
    return served.map((row) => edits[targetId(row)] ?? row);
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
        // The status code is kept across a failed probe — the last good snapshot
        // is still the best thing known about the host — so these two are what
        // say the host is not answering *now*.
        failure: r.observed?.failure,
        last_error: r.observed?.error,
        response_time: r.http?.response_time,
        open_ports: r.network?.open_ports?.map(String),
        known_paths: r.http?.known_paths,
        login_methods: r.http?.login_methods,
        findings: r.scan?.last_findings,
        dirty: targetId(r) in edits,
      })),
    [edits, rows],
  );

  const applyBulk = useCallback(
    (edit: BulkEdit) => {
      const selected = new Set(selectedIds);
      const current = new Map(rows.map((row) => [targetId(row), row]));
      const stored = new Map(served.map((row) => [targetId(row), row]));
      setEdits((prev) => {
        const next = { ...prev };
        for (const id of selected) {
          const row = current.get(id);
          if (!row) continue;
          const edited = applyEdit(row, edit);
          // An edit that lands back on what the database already has is not a
          // change, and leaving it in would keep claiming unsaved work.
          const saved = stored.get(id);
          if (saved && sameDefinition(edited, saved)) delete next[id];
          else next[id] = edited;
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
    rows.forEach((r) => sel.has(targetId(r)) && r.tags.forEach((t) => tags.add(t)));
    return [...tags].sort();
  }, [rows, selectedIds]);

  const scannedCount = tableRows.filter((r) => r.last_scan).length;
  const savedTargetIds = useMemo(() => served.map(targetId), [served]);
  const hostRows = useMemo(
    () => rows.filter((row) => targetKind(row) === "host"),
    [rows],
  );
  const selectedHosts = useMemo(() => {
    const selected = new Set(selectedIds);
    return hostRows
      .filter((row) => selected.has(targetId(row)))
      .map(targetHost);
  }, [hostRows, selectedIds]);

  const scanActive = scan?.phase === "queued" || scan?.phase === "running";
  const scanLabel = selectedIds.length
    ? `${scanActive ? "Queue" : "Scan"} ${selectedIds.length} selected`
    : scanActive
      ? "Queue scan"
      : "Scan now";

  return (
    <AppShell
      bodyHeader={
        <div className="flex min-w-0 items-baseline gap-3">
          <h1 className="text-lg font-semibold">Target Inventory</h1>
          <span className="truncate text-sm text-muted-foreground">
            {rows.length} targets · {scannedCount} scanned ·{" "}
            {tagVocabulary.length} tags
          </span>
        </div>
      }
      bodyActions={
        <div className="flex items-center gap-3">
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
          <Button size="sm" onClick={() => setAddOpen(true)} disabled={busy}>
            Add target
          </Button>
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
        </div>
      }
      // The inventory table is the widest in the app — target, kind, class,
      // tags, profiles, app, cluster, status, ports, paths, findings and two
      // timestamps — so the centred default spent most of a wide window on
      // margins while the columns fought over what was left.
      contentWidth="full"
      contentClassName="overflow-hidden p-3"
    >
      {/* h-full, not flex-1: AppShell puts its content-width wrapper between
          `main` and these children, and that wrapper is a block — so a flex
          class on contentClassName never reaches here and `flex-1` has no flex
          context to resolve against. Taking the wrapper's height directly is
          what lets the table own the scroll and keep its header pinned;
          without it the rows past the first screen are simply clipped. */}
      <div className="flex h-full min-h-0 flex-col">
      <AddTargetDialog
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onCreated={() => void load()}
        tagVocabulary={tagVocabulary}
      />

      <DiscoverDialog
        open={discoverOpen}
        onClose={() => setDiscoverOpen(false)}
        onDiscovered={() => void load()}
      />

      <PingDialog
        open={pingOpen}
        onClose={() => setPingOpen(false)}
        rows={tableRows.filter((row) => targetKind(row) === "host")}
        selectedHosts={selectedHosts}
        onProbed={refreshHosts}
      />

      {scanOpen && (
        <ScanDialog
          open={scanOpen}
          onClose={() => setScanOpen(false)}
          rows={rows}
          savedTargetIds={savedTargetIds}
          selectedTargetIds={selectedIds}
          status={scan}
          onStatus={setScan}
          onOpenScan={(file) => {
            setScanOpen(false);
            onOpenScan(file);
          }}
        />
      )}

      <DataTable<TableRow>
          className="min-h-0 flex-1"
          data={tableRows}
          columns={columns}
          getRowId={targetId}
          getRowHref={(row) => `/inventory/${encodeURIComponent(targetId(row))}`}
          onRowClick={(row) => onOpenTarget(targetId(row))}
          // The controls come from the entity's own filter declaration and the
          // database answers them, so these rows arrived narrowed. DataTable
          // never applies caller-supplied filters itself, which is what lets
          // the search box keep narrowing the result further in the browser.
          externalFilters={filters}
          showGlobalFilter
          globalFilter={query}
          onGlobalFilterChange={setQuery}
          globalFilterPlaceholder="Search targets, hosts, tags, apps…"
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
      </div>
    </AppShell>
  );
}
