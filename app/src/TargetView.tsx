import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ComponentProps,
  type ReactNode,
} from "react";
import {
  Badge,
  Button,
  JsonSchemaForm,
  KeyValueList,
  Panel,
  Section,
} from "@flanksource/clicky-ui";
import {
  curatedTarget,
  type ProfileDocument,
  type TargetDocument,
} from "./types";
import {
  fetchProfiles,
  fetchTarget,
  fetchTargetSchema,
  saveTarget,
} from "./api";
import { ScanDialog } from "./ScanDialog";
import { useScanStatus } from "./useScanStatus";

type TargetSchema = ComponentProps<typeof JsonSchemaForm>["schema"];
type TargetPreExtension = NonNullable<
  ComponentProps<typeof JsonSchemaForm>["pre"]
>[number];
type Props = { host: string; onBack: () => void };

const hideInactiveReason: TargetPreExtension = (field, context) =>
  field.key === "reason" && context.rootValue?.class !== "deactivated"
    ? null
    : field;
const DISCOVERY_PROFILE = ["discovery"] as const;
type ScanMode = "discovery" | "nuclei";

function display(value: unknown): ReactNode {
  if (value === undefined || value === null || value === "") return "—";
  if (Array.isArray(value)) return value.length > 0 ? value.join(", ") : "—";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function recordItems(record: Record<string, unknown> | undefined) {
  return Object.entries(record ?? {}).map(([key, value]) => ({
    key,
    label: key.replaceAll("_", " "),
    value: display(value),
  }));
}

function MachinePanel({
  title,
  value,
}: {
  title: string;
  value?: Record<string, unknown>;
}) {
  return (
    <Panel title={title}>
      <KeyValueList
        items={recordItems(value)}
        emptyMessage="No observation recorded."
      />
    </Panel>
  );
}

function Preview({ target }: { target: TargetDocument }) {
  const definition = [
    {
      key: "class",
      label: "Class",
      value: <Badge tone="info">{target.class}</Badge>,
    },
    { key: "app", label: "Application", value: display(target.app) },
    { key: "cluster", label: "Cluster", value: display(target.cluster) },
    { key: "source", label: "Source", value: display(target.source) },
    { key: "profiles", label: "Profiles", value: display(target.profiles) },
    { key: "ports", label: "Ports", value: display(target.ports) },
    { key: "tags", label: "Tags", value: display(target.tags) },
    { key: "notes", label: "Notes", value: display(target.notes) },
    {
      key: "reason",
      label: "Deactivation reason",
      value: display(target.reason),
    },
  ];
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel title="Target definition">
        <KeyValueList items={definition} />
      </Panel>
      <Panel title="Observed HTTP">
        <KeyValueList
          items={[
            ...recordItems(
              target.observed as Record<string, unknown> | undefined,
            ),
            ...recordItems(target.http as Record<string, unknown> | undefined),
          ]}
          emptyMessage="No HTTP observation recorded."
        />
      </Panel>
      <MachinePanel
        title="Network"
        value={target.network as Record<string, unknown> | undefined}
      />
      <MachinePanel
        title="Technology"
        value={target.tech as Record<string, unknown> | undefined}
      />
      <Section title="TLS" defaultOpen={false} className="lg:col-span-2">
        <KeyValueList
          items={recordItems(target.tls)}
          emptyMessage="No TLS certificate observation recorded."
        />
      </Section>
      <MachinePanel
        title="Scan"
        value={target.scan as Record<string, unknown> | undefined}
      />
    </div>
  );
}

export function TargetView({ host, onBack }: Props) {
  const [target, setTarget] = useState<TargetDocument | null>(null);
  const [schema, setSchema] = useState<TargetSchema | null>(null);
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [editing, setEditing] = useState(false);
  const [scanMode, setScanMode] = useState<ScanMode | null>(null);
  const [scanRunMode, setScanRunMode] = useState<ScanMode | null>(null);
  const [nucleiProfiles, setNucleiProfiles] = useState<ProfileDocument[]>([]);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refreshTarget = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setTarget(await fetchTarget(host));
    } catch (nextError) {
      setError((nextError as Error).message);
    } finally {
      setBusy(false);
    }
  }, [host]);

  const {
    status: scan,
    error: scanError,
    setStatus: setScan,
  } = useScanStatus((finished) => {
    if (finished.phase === "done" && finished.hosts.includes(host)) {
      void refreshTarget();
    }
  });

  useEffect(() => {
    let active = true;
    setBusy(true);
    setError(null);
    Promise.all([fetchTarget(host), fetchTargetSchema()])
      .then(([nextTarget, nextSchema]) => {
        if (!active) return;
        setTarget(nextTarget);
        setSchema(nextSchema as TargetSchema);
      })
      .catch((nextError: Error) => active && setError(nextError.message))
      .finally(() => active && setBusy(false));
    return () => {
      active = false;
    };
  }, [host]);

  useEffect(() => {
    let active = true;
    setProfileError(null);
    fetchProfiles()
      .then((profiles) => {
        if (!active) return;
        const next = profiles.filter((profile) => profile.engine === "nuclei");
        if (next.length === 0) throw new Error("No Nuclei profiles found");
        setNucleiProfiles(next);
      })
      .catch((nextError: Error) => active && setProfileError(nextError.message));
    return () => {
      active = false;
    };
  }, []);

  const dirty = useMemo(() => {
    if (!target || !draft) return false;
    return (
      JSON.stringify(curatedTarget(draft as TargetDocument)) !==
      JSON.stringify(curatedTarget(target))
    );
  }, [draft, target]);

  useEffect(() => {
    if (!dirty) return;
    const warn = (event: BeforeUnloadEvent) => event.preventDefault();
    const guardLink = (event: MouseEvent) => {
      const anchor = (event.target as Element | null)?.closest("a[href]");
      if (!anchor || window.confirm("Discard unsaved target changes?")) return;
      event.preventDefault();
      event.stopPropagation();
    };
    window.addEventListener("beforeunload", warn);
    document.addEventListener("click", guardLink, true);
    return () => {
      window.removeEventListener("beforeunload", warn);
      document.removeEventListener("click", guardLink, true);
    };
  }, [dirty]);

  const back = () => {
    if (!dirty || window.confirm("Discard unsaved target changes?")) onBack();
  };

  const initialNucleiProfile =
    target?.profiles.find((name) =>
      nucleiProfiles.some((profile) => profile.name === name),
    ) ?? nucleiProfiles[0]?.name;
  const dialogStatus =
    scan?.phase === "running" || scanRunMode === scanMode ? scan : null;

  const openScan = (mode: ScanMode) => {
    setScanRunMode(null);
    setScanMode(mode);
  };

  const save = async () => {
    if (!draft) throw new Error("target editor has no draft");
    setBusy(true);
    setError(null);
    try {
      const updated = await saveTarget(
        host,
        curatedTarget(draft as TargetDocument),
      );
      setTarget(updated);
      setDraft(null);
      setEditing(false);
    } catch (nextError) {
      setError((nextError as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="h-full overflow-auto bg-background text-foreground">
      <header className="sticky top-0 z-10 flex items-center gap-3 border-b border-border bg-background px-4 py-3">
        <Button variant="outline" size="sm" onClick={back}>
          Back to inventory
        </Button>
        <div className="min-w-0">
          <h1 className="truncate text-lg font-semibold">{host}</h1>
          <p className="text-xs text-muted-foreground">
            Canonical inventory target
          </p>
        </div>
        <span className="flex-1" />
        {error || profileError || scanError ? (
          <span role="alert" className="text-sm text-destructive">
            {error ?? profileError ?? scanError}
          </span>
        ) : null}
        {editing ? (
          <>
            {dirty ? (
              <span className="text-sm text-amber-600">Unsaved changes</span>
            ) : null}
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setEditing(false);
                setDraft(null);
              }}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              loading={busy}
              disabled={busy || !dirty}
              onClick={() => void save()}
            >
              Save changes
            </Button>
          </>
        ) : (
          <>
            <Button
              variant="outline"
              size="sm"
              disabled={!target}
              loading={
                scan?.phase === "running" &&
                scan.profile === "discovery" &&
                scan.hosts.includes(host)
              }
              onClick={() => openScan("discovery")}
            >
              Rescan discovery
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!target || !initialNucleiProfile}
              loading={
                scan?.phase === "running" &&
                scan.profile !== "discovery" &&
                scan.hosts.includes(host)
              }
              onClick={() => openScan("nuclei")}
            >
              Run Nuclei scan
            </Button>
            <Button
              size="sm"
              disabled={!target || !schema || busy}
              onClick={() => {
                setDraft({ ...target });
                setEditing(true);
              }}
            >
              Edit target
            </Button>
          </>
        )}
      </header>
      {target && scanMode ? (
        <ScanDialog
          open
          onClose={() => setScanMode(null)}
          rows={[target]}
          savedHosts={[target.host]}
          selectedHosts={[target.host]}
          status={dialogStatus}
          onStatus={(next) => {
            setScanRunMode(scanMode);
            setScan(next);
          }}
          availableProfiles={
            scanMode === "discovery"
              ? DISCOVERY_PROFILE
              : nucleiProfiles.map((profile) => profile.name)
          }
          initialProfile={
            scanMode === "discovery" ? "discovery" : initialNucleiProfile
          }
          allowAllTargets={false}
          nucleiProfiles={nucleiProfiles}
          editableNucleiProfile={scanMode === "nuclei"}
        />
      ) : null}
      <main className="mx-auto max-w-6xl p-4">
        {busy && !target ? (
          <p className="text-sm text-muted-foreground">Loading target…</p>
        ) : null}
        {!editing && target ? <Preview target={target} /> : null}
        {editing && target && schema && draft ? (
          <Panel title="Edit curated definition">
            <JsonSchemaForm
              schema={schema}
              value={draft}
              onChange={(next) => setDraft({ ...target, ...next })}
              hideReadOnlyFields
              requiredFirst
              pre={[hideInactiveReason]}
              layout={{ mode: "inline", valueMaxWidth: "48rem" }}
              idPrefix="target"
            />
          </Panel>
        ) : null}
      </main>
    </div>
  );
}
