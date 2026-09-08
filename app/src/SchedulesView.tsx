import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@flanksource/clicky-ui/components";
import { fetchEngines, fetchProfiles } from "./api";
import { fetchScans } from "./api-scans";
import {
  deleteSchedule,
  fetchSchedules,
  saveSchedule,
  type ScanSchedule,
} from "./api-schedules";
import { TargetSelector } from "./TargetSelector";
import type { Engine, Profile } from "./types";

type Props = {
  selected?: string;
  onSelect: (name?: string) => void;
  onOpenScan: (id: string) => void;
};

/** Durable configuration is edited separately from the periodically refreshed execution status. */
export function SchedulesView({ selected, onSelect, onOpenScan }: Props) {
  const schedules = useQuery({
    queryKey: ["schedules"],
    queryFn: fetchSchedules,
    refetchInterval: 5000,
  });
  const engines = useQuery({
    queryKey: ["schedule-engines"],
    queryFn: () => fetchEngines("scan"),
  });
  const profiles = useQuery({
    queryKey: ["schedule-profiles"],
    queryFn: () => fetchProfiles({ kind: "scan" }),
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const isNew = selected === "+";
  const stored = schedules.data?.find((entry) => entry.name === selected);
  const failure =
    error ??
    schedules.error?.message ??
    engines.error?.message ??
    profiles.error?.message;

  const save = async (draft: ScanSchedule) => {
    setBusy(true);
    setError(undefined);
    try {
      const saved = await saveSchedule(draft, isNew);
      await schedules.refetch();
      onSelect(saved.name);
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!stored) return;
    setBusy(true);
    setError(undefined);
    try {
      await deleteSchedule(stored.name);
      onSelect(undefined);
      await schedules.refetch();
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <div>
          <h1 className="text-lg font-semibold">Scan schedules</h1>
          <p className="text-xs text-muted-foreground">
            Recurring scans saved in the database. Changes take effect without
            restarting.
          </p>
        </div>
        <span className="flex-1" />
        <span className="text-xs text-muted-foreground">
          {schedules.data?.length ?? 0} schedules
        </span>
        <Button
          size="sm"
          disabled={busy}
          onClick={() => {
            setError(undefined);
            onSelect("+");
          }}
        >
          New schedule
        </Button>
      </header>
      {failure && (
        <p
          role="alert"
          className="border-b border-border p-3 text-sm text-destructive"
        >
          {failure}
        </p>
      )}
      <div className="flex min-h-0 flex-1 flex-col md:flex-row">
        <nav
          aria-label="Schedules"
          className="max-h-48 shrink-0 overflow-y-auto border-b border-border md:max-h-none md:w-64 md:border-r md:border-b-0"
        >
          {schedules.isPending && (
            <p className="p-4 text-sm text-muted-foreground">
              Loading schedules…
            </p>
          )}
          {schedules.data?.length === 0 && (
            <p className="p-4 text-sm text-muted-foreground">
              No schedules yet. Create one to run scans automatically.
            </p>
          )}
          {schedules.data?.map((entry) => (
            <button
              key={entry.name}
              type="button"
              disabled={busy}
              aria-current={selected === entry.name}
              onClick={() => {
                setError(undefined);
                onSelect(entry.name);
              }}
              className={`flex w-full flex-col gap-1 border-b border-border p-3 text-left text-sm ${selected === entry.name ? "bg-muted" : ""}`}
            >
              <span className="flex flex-wrap items-center gap-2 font-medium">
                {entry.name}
                <span className="rounded bg-muted px-1.5 text-xs font-normal">
                  {entry.enabled ? "Enabled" : "Disabled"}
                </span>
              </span>
              <span className="text-xs text-muted-foreground">
                {entry.engine} / {entry.profile}
              </span>
              <span className="text-xs text-muted-foreground">
                {entry.cron} · {entry.timezone}
              </span>
              {entry.lastError && (
                <span className="text-xs text-destructive">
                  Last attempt failed
                </span>
              )}
            </button>
          ))}
        </nav>
        <main className="min-w-0 flex-1 overflow-y-auto p-4">
          {selected && !isNew && !stored && !schedules.isPending ? (
            <p role="alert">Schedule not found. It may have been deleted.</p>
          ) : (isNew || stored) && engines.data && profiles.data ? (
            <ScheduleEditor
              key={selected}
              stored={stored}
              engines={engines.data}
              profiles={profiles.data}
              busy={busy}
              onSave={save}
              onDelete={remove}
              onOpenScan={onOpenScan}
            />
          ) : (
            <p className="text-sm text-muted-foreground">
              Select a schedule to view or edit it.
            </p>
          )}
        </main>
      </div>
    </div>
  );
}

type EditorProps = {
  stored?: ScanSchedule;
  engines: Engine[];
  profiles: Profile[];
  busy: boolean;
  onSave: (draft: ScanSchedule) => Promise<void>;
  onDelete: () => Promise<void>;
  onOpenScan: (id: string) => void;
};

/** Polling updates status, never the unsaved form. Changing the addressed schedule remounts it. */
function ScheduleEditor({
  stored,
  engines,
  profiles,
  busy,
  onSave,
  onDelete,
  onOpenScan,
}: EditorProps) {
  const [draft, setDraft] = useState<ScanSchedule>(
    () =>
      stored ?? {
        name: "",
        enabled: true,
        engine: "nuclei",
        profile: "safe",
        targets: { class: ["non-prod"] },
        cron: "0 2 * * *",
        timezone: "UTC",
        confirm: false,
      },
  );
  const [validTargets, setValidTargets] = useState(true);
  const [nameTouched, setNameTouched] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const history = useQuery({
    queryKey: ["schedule-scans", stored?.id],
    queryFn: () => fetchScans({ "creator-schedule-id": stored!.id!, limit: 3 }),
    enabled: !!stored?.id,
    refetchInterval: 5000,
  });
  const set = (patch: Partial<ScanSchedule>) =>
    setDraft((current) => ({ ...current, ...patch }));
  const available = profiles.filter(
    (profile) => profile.engine === draft.engine,
  );
  const profile = available.find((entry) => entry.name === draft.profile);
  const input =
    "mt-1 w-full rounded border border-border bg-background px-3 py-2 text-sm disabled:opacity-60";
  const nameError = !draft.name
    ? "Enter a schedule name."
    : !/^[a-z0-9][a-z0-9-]*$/.test(draft.name)
      ? "Use lowercase letters, digits and dashes, starting with a letter or digit."
      : undefined;
  const saveError =
    nameError ??
    (!validTargets
      ? "Fix the target selector JSON before saving."
      : undefined) ??
    (draft.enabled && !profile ? "Choose an available scanning profile." : undefined) ??
    (!draft.cron.trim() ? "Enter a cron frequency." : undefined) ??
    (!draft.timezone ? "Choose a timezone." : undefined);
  const canSave = !saveError;
  const timezones = [
    ...new Set(["UTC", draft.timezone, ...Intl.supportedValuesOf("timeZone")]),
  ].filter(Boolean);
  return (
    <form
      className="flex max-w-4xl flex-col gap-5"
      onSubmit={(event) => {
        event.preventDefault();
        void onSave(draft);
      }}
    >
      <h2 className="text-base font-semibold">
        {stored ? "Edit schedule" : "New schedule"}
      </h2>
      <fieldset disabled={busy} className="flex flex-col gap-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm font-medium">
            Name
            <input
              required
              pattern="[a-z0-9][a-z0-9-]*"
              aria-label="Name"
              aria-invalid={nameTouched && !!nameError}
              aria-describedby={
                nameTouched && nameError
                  ? "schedule-name-error"
                  : "schedule-name-help"
              }
              className={`${input} aria-invalid:border-[var(--destructive)]`}
              value={draft.name}
              disabled={!!stored}
              onBlur={() => setNameTouched(true)}
              onChange={(event) => {
                setNameTouched(true);
                set({ name: event.target.value });
              }}
            />
            <span
              id="schedule-name-help"
              className="text-xs font-normal text-muted-foreground"
            >
              Lowercase letters, digits and dashes. The name stays fixed after
              creation.
            </span>
            {nameTouched && nameError && (
              <span
                id="schedule-name-error"
                role="alert"
                className="mt-1 block text-xs font-normal text-destructive"
              >
                {nameError}
              </span>
            )}
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(event) => set({ enabled: event.target.checked })}
            />
            Enabled
          </label>
          <label className="text-sm font-medium">
            Scanning engine
            <select
              aria-label="Scanning engine"
              className={input}
              value={draft.engine}
              onChange={(event) =>
                set({
                  engine: event.target.value,
                  profile:
                    profiles.find((p) => p.engine === event.target.value)
                      ?.name ?? "",
                  confirm: false,
                })
              }
            >
              {engines.map((engine) => (
                <option key={engine.name} value={engine.name}>
                  {engine.title}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm font-medium">
            Profile
            <select
              required={draft.enabled}
              aria-label="Profile"
              className={input}
              value={draft.profile}
              onChange={(event) =>
                set({ profile: event.target.value, confirm: false })
              }
            >
              {!profile && (
                <option value={draft.profile}>
                  {draft.profile || "Choose a profile"} (unavailable)
                </option>
              )}
              {available.map((entry) => (
                <option key={entry.name} value={entry.name}>
                  {entry.name}
                  {entry.intrusive ? " · intrusive" : ""}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm font-medium">
            Cron frequency
            <input
              required
              aria-label="Cron frequency"
              className={input}
              value={draft.cron}
              onChange={(event) => set({ cron: event.target.value })}
            />
            <span className="text-xs font-normal text-muted-foreground">
              Minute hour day month weekday. Nightly: 0 2 * * *; monthly: 0 3 1
              * *.
            </span>
          </label>
          <label className="text-sm font-medium">
            Timezone
            <select
              required
              aria-label="Timezone"
              className={input}
              value={draft.timezone}
              onChange={(event) => set({ timezone: event.target.value })}
            >
              {timezones.map((timezone) => (
                <option key={timezone} value={timezone}>
                  {timezone}
                </option>
              ))}
            </select>
            <span className="text-xs font-normal text-muted-foreground">
              An IANA timezone; daylight-saving changes follow its calendar.
            </span>
          </label>
        </div>
        <div className="rounded border border-border p-3">
          <TargetSelector
            targets={draft.targets}
            onChange={(targets) => set({ targets: targets ?? {} })}
            onValidityChange={setValidTargets}
          />
        </div>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={draft.confirm}
            onChange={(event) => set({ confirm: event.target.checked })}
          />
          <span>
            Authorize intrusive scanning of production, public, or unclassified
            targets.
            <span className="block text-xs text-muted-foreground">
              Without this authorization, existing scan safety gates refuse
              intrusive runs against these targets.
            </span>
          </span>
        </label>
      </fieldset>
      {stored && (
        <section
          aria-label="Schedule execution"
          className="rounded border border-border bg-muted/30 p-3 text-sm"
        >
          <p>
            Next run:{" "}
            {stored.nextRun
              ? new Date(stored.nextRun).toLocaleString()
              : "Disabled"}
          </p>
          <p>
            Last attempt:{" "}
            {stored.lastRun
              ? new Date(stored.lastRun).toLocaleString()
              : "Not run yet"}
          </p>
          <h3 className="mt-3 font-medium">Recent scans (latest 3)</h3>
          {history.isPending ? <p>Loading scans…</p> : history.isError ? (
            <p role="alert">Unable to load scan history.</p>
          ) : !history.data?.length ? <p>No recorded scans yet.</p> : (
            <div className="mt-2 overflow-x-auto">
              <table aria-label="Recent scans" className="w-full text-left text-sm">
                <thead className="border-b border-border text-xs text-muted-foreground">
                  <tr>
                    <th scope="col" className="py-2 pr-4 font-medium">Scan</th>
                    <th scope="col" className="py-2 pr-4 font-medium">Status</th>
                    <th scope="col" className="py-2 font-medium">Started</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {history.data.map((run) => (
                    <tr key={run.id}>
                      <td className="py-2 pr-4">
                        <button
                          type="button"
                          className="block max-w-64 truncate text-primary underline"
                          title={run.name}
                          onClick={() => onOpenScan(run.id)}
                        >
                          {run.name}
                        </button>
                      </td>
                      <td className="whitespace-nowrap py-2 pr-4">{run.phase}</td>
                      <td className="whitespace-nowrap py-2">
                        {new Date(run.startedAt).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {stored.lastError && (
            <p role="alert" className="mt-2 text-destructive">
              {stored.lastError}
            </p>
          )}
        </section>
      )}
      <p className="text-xs text-muted-foreground">
        Save applies changes immediately. Disabling or deleting prevents future
        attempts; an already accepted scan continues. Firings missed while busy
        are skipped.
      </p>
      {saveError && (
        <p aria-live="polite" className="text-sm text-destructive">
          Cannot save: {saveError}
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" disabled={busy || !canSave}>
          {busy ? "Saving…" : "Save schedule"}
        </Button>
        {stored && !confirmDelete && (
          <Button
            type="button"
            variant="outline"
            disabled={busy}
            onClick={() => setConfirmDelete(true)}
          >
            Delete schedule
          </Button>
        )}
        {confirmDelete && (
          <>
            <span className="self-center text-sm">
              Delete this schedule permanently?
            </span>
            <Button
              type="button"
              variant="destructive"
              disabled={busy}
              onClick={() => void onDelete()}
            >
              Confirm delete
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={busy}
              onClick={() => setConfirmDelete(false)}
            >
              Keep schedule
            </Button>
          </>
        )}
      </div>
    </form>
  );
}
