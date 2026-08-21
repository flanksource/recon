import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Button, Panel, Section } from "@flanksource/clicky-ui/components";
import { Badge, KeyValueList } from "@flanksource/clicky-ui/data";
import {
  curatedTarget,
  targetKind,
  type Engine,
  type CredentialMutation,
  type Profile,
  type TargetDocument,
  type TargetUpdate,
} from "./types";
import {
  fetchEngines,
  fetchProfiles,
  fetchTarget,
  fetchTargetSchema,
  saveTarget,
} from "./api";
import { ScanDialog } from "./ScanDialog";
import { TargetEditor } from "./TargetEditor";
import { useScanStatus } from "./useScanStatus";

type Props = { id: string; onBack: () => void };
// Discovery is no longer a scan profile but a separate operation, so the two
// buttons open the same dialog in different modes rather than picking a profile.
type ScanMode = "discovery" | "scan";

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
    { key: "id", label: "ID", value: display(target.id) },
    { key: "kind", label: "Kind", value: display(targetKind(target)) },
    ...(target.kind === "provider-context"
      ? [
          { key: "provider", label: "Provider", value: display(target.provider) },
          {
            key: "credentialMode",
            label: "Credentials",
            value: display(target.credentialMode),
          },
          {
            key: "arguments",
            label: "Provider scope",
            value: display(target.arguments),
          },
        ]
      : [{ key: "host", label: "Host", value: display(target.host) }]),
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

export function resolveProviderContextEngine(
  engines: Engine[],
  provider: string,
): Engine {
  const matches = engines.filter(
    (engine) =>
      engine.options.discriminator === "provider" &&
      engine.options.variants.some(
        (variant) => variant.id === provider && variant.contextSchema,
      ),
  );
  if (matches.length === 0) {
    throw new Error(`No scan engine defines context options for provider "${provider}"`);
  }
  if (matches.length > 1) {
    throw new Error(`Multiple scan engines define context options for provider "${provider}"`);
  }
  return matches[0];
}

function editableDefinition(target: TargetDocument): TargetUpdate {
  return {
    ...curatedTarget(target),
    ...(target.kind === "provider-context"
      ? {
          credentialMode: target.credentialMode,
          arguments: target.arguments ?? {},
        }
      : {}),
  };
}

export function TargetView({ id, onBack }: Props) {
  const [target, setTarget] = useState<TargetDocument | null>(null);
  const [schema, setSchema] = useState<Record<string, unknown> | null>(null);
  const [draft, setDraft] = useState<Record<string, unknown> | null>(null);
  const [editing, setEditing] = useState(false);
  const [scanMode, setScanMode] = useState<ScanMode | null>(null);
  const [scanRunMode, setScanRunMode] = useState<ScanMode | null>(null);
  const [scanProfiles, setScanProfiles] = useState<Profile[]>([]);
  const [scanEngines, setScanEngines] = useState<Engine[]>([]);
  const [catalogLoaded, setCatalogLoaded] = useState(false);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [credentialMutation, setCredentialMutation] =
    useState<CredentialMutation>(undefined);

  const refreshTarget = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setTarget(await fetchTarget(id));
    } catch (nextError) {
      setError((nextError as Error).message);
    } finally {
      setBusy(false);
    }
  }, [id]);

  const {
    status: scan,
    error: scanError,
    setStatus: setScan,
  } = useScanStatus((finished) => {
    if (finished.phase === "done" && finished.hosts.includes(id)) {
      void refreshTarget();
    }
  });

  useEffect(() => {
    let active = true;
    setBusy(true);
    setError(null);
    Promise.all([fetchTarget(id), fetchTargetSchema()])
      .then(([nextTarget, nextSchema]) => {
        if (!active) return;
        setTarget(nextTarget);
        setSchema(nextSchema);
      })
      .catch((nextError: Error) => active && setError(nextError.message))
      .finally(() => active && setBusy(false));
    return () => {
      active = false;
    };
  }, [id]);

  useEffect(() => {
    let active = true;
    setCatalogLoaded(false);
    setProfileError(null);
    Promise.all([fetchProfiles({ kind: "scan" }), fetchEngines("scan")])
      .then(([profiles, engines]) => {
        if (!active) return;
        setScanProfiles(profiles);
        setScanEngines(engines);
        if (profiles.length === 0) setProfileError("No scan profiles found");
      })
      .catch((nextError: Error) => active && setProfileError(nextError.message))
      .finally(() => active && setCatalogLoaded(true));
    return () => {
      active = false;
    };
  }, []);

  const dirty = useMemo(() => {
    if (!target || !draft) return false;
    if (credentialMutation !== undefined) return true;
    return (
      JSON.stringify(editableDefinition(draft as TargetDocument)) !==
      JSON.stringify(editableDefinition(target))
    );
  }, [credentialMutation, draft, target]);

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

  const canScan = scanProfiles.length > 0;
  const providerEngine = useMemo(() => {
    if (!catalogLoaded || target?.kind !== "provider-context" || !target.provider) {
      return null;
    }
    try {
      return { engine: resolveProviderContextEngine(scanEngines, target.provider) };
    } catch (cause) {
      return { error: (cause as Error).message };
    }
  }, [catalogLoaded, scanEngines, target]);
  const dialogStatus =
    scan?.phase === "queued" ||
    scan?.phase === "running" ||
    scanRunMode === scanMode
      ? scan
      : null;

  const openScan = (mode: ScanMode) => {
    setScanRunMode(null);
    setScanMode(mode);
  };

  const save = async () => {
    if (!draft) throw new Error("target editor has no draft");
    setBusy(true);
    setError(null);
    try {
      const updated = await saveTarget(id, {
        ...editableDefinition(draft as TargetDocument),
        ...(credentialMutation !== undefined
          ? { credentials: credentialMutation }
          : {}),
      });
      setTarget(updated);
      setDraft(null);
      setCredentialMutation(undefined);
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
          <h1 className="truncate text-lg font-semibold">{id}</h1>
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
                setCredentialMutation(undefined);
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
              disabled={!target || target.kind === "provider-context"}
              onClick={() => openScan("discovery")}
            >
              Rescan discovery
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={!target || !canScan}
              onClick={() => openScan("scan")}
            >
              Run scan
            </Button>
            <Button
              size="sm"
              disabled={!target || !schema || busy}
              onClick={() => {
                setDraft({ ...target });
                setCredentialMutation(undefined);
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
          savedTargetIds={[id]}
          selectedTargetIds={[id]}
          preferredProfile={target.profiles[0]}
          status={dialogStatus}
          onStatus={(next) => {
            setScanRunMode(scanMode);
            setScan(next);
          }}
          allowAllTargets={false}
          discoveryOnly={scanMode === "discovery"}
          editableProfile={scanMode === "scan"}
        />
      ) : null}
      <main className="mx-auto max-w-6xl p-4">
        {busy && !target ? (
          <p className="text-sm text-muted-foreground">Loading target…</p>
        ) : null}
        {!editing && target ? <Preview target={target} /> : null}
        {editing && target && schema && draft ? (
          <TargetEditor
            id={id}
            target={target}
            schema={schema}
            draft={draft}
            setDraft={(update) => setDraft((current) => (current ? update(current) : current))}
            catalogLoaded={catalogLoaded}
            providerEngine={providerEngine}
            credentialMutation={credentialMutation}
            onCredentialChange={setCredentialMutation}
          />
        ) : null}
      </main>
    </div>
  );
}
