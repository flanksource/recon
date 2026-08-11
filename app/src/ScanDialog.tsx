import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Button,
  Modal,
  SegmentedControl,
  Select,
} from "@flanksource/clicky-ui";
import {
  cancelScan,
  fetchEngines,
  fetchProfiles,
  runDiscovery,
  saveProfile,
  startScan,
} from "./api";
import { ProfileConfig, sameConfig } from "./ProfileConfig";
import {
  DiscoveryProfiles,
  PROFILE_NAME,
  describeSelection,
  discoveryRunFields,
  useDiscoveryProfiles,
} from "./DiscoveryProfiles";
import { DiscoveryRunSummary } from "./DiscoveryRunSummary";
import { ScanRunStatus } from "./ScanRunStatus";
import { TemplateSummary, usePreview } from "./TemplatePreview";
import type { Discover, Engine, Profile, ScanStatus, TargetRow } from "./types";

// Classes where a scan would send malicious payloads at something real — same
// gate the server enforces. A host not yet written to the inventory is
// treated the same way: the server cannot verify its class, so an unsaved
// "non-prod" is not proof of anything.
const CONFIRM_CLASSES = new Set(["prod", "public", "unclassified"]);
const DEFAULT_ENGINE = "nuclei";
const DEFAULT_PROFILE = "safe";

type Scope = "selected" | "all";

type Props = {
  open: boolean;
  onClose: () => void;
  rows: TargetRow[];
  /** Hosts persisted in the inventory — anything else is an unsaved addition. */
  savedHosts: string[];
  selectedHosts: string[];
  status: ScanStatus | null;
  onStatus: (status: ScanStatus) => void;
  onOpenScan?: (id: string) => void;
  allowAllTargets?: boolean;
  /** Re-probes the selected hosts via discovery instead of running a scan engine. */
  discoveryOnly?: boolean;
  /**
   * Lets this run's profile configuration be tweaked before starting. On by
   * default: tweaks are run-only, so offering them costs nothing that a stored
   * profile has to be protected from.
   */
  editableProfile?: boolean;
};

export function ScanDialog({
  open,
  onClose,
  rows,
  savedHosts,
  selectedHosts,
  status,
  onStatus,
  onOpenScan,
  allowAllTargets = true,
  discoveryOnly = false,
  editableProfile = true,
}: Props) {
  const [scope, setScope] = useState<Scope>("selected");
  const [engines, setEngines] = useState<Engine[]>([]);
  const [engineName, setEngineName] = useState(DEFAULT_ENGINE);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profileName, setProfileName] = useState(DEFAULT_PROFILE);
  const [runConfig, setRunConfig] = useState<Record<string, unknown> | null>(
    null,
  );
  const [newProfileName, setNewProfileName] = useState("");
  const [keeping, setKeeping] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [discoverResult, setDiscoverResult] = useState<Discover | null>(null);
  const [editingDiscovery, setEditingDiscovery] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  // Every run here sweeps first — a scan discovers its endpoints before it
  // touches them — so the discovery profiles belong in this dialog too, not
  // only in the discover one.
  const discoveryProfiles = useDiscoveryProfiles(open);

  const scanActive = status?.phase === "queued" || status?.phase === "running";
  const controlsLocked = discoveryOnly ? discovering : starting;
  // A discovery rescan reads no scan catalog; every other run needs the chosen
  // profile in hand before it can say what configuration it is running with.
  const catalogLoaded =
    discoveryOnly || !editableProfile || runConfig !== null;

  // Scope defaults on open only. Re-deriving it while the dialog is open would silently
  // widen a run to every target if the selection changed underneath it.
  const wasOpen = useRef(false);
  useEffect(() => {
    const opened = open && !wasOpen.current;
    wasOpen.current = open;
    if (!opened) return;
    setError(null);
    setConfirmed(false);
    setDiscoverResult(null);
    setEditingDiscovery(false);
    setScope(selectedHosts.length ? "selected" : "all");
  }, [open, selectedHosts.length]);

  useEffect(() => {
    if (!open || discoveryOnly) return;
    let cancelled = false;
    fetchEngines("scan")
      .then((list) => {
        if (cancelled) return;
        setEngines(list);
        setEngineName((current) =>
          list.some((engine) => engine.name === current)
            ? current
            : (list.find((engine) => engine.name === DEFAULT_ENGINE)?.name ??
              list[0]?.name ??
              DEFAULT_ENGINE),
        );
      })
      .catch((cause) => !cancelled && setError((cause as Error).message));
    return () => {
      cancelled = true;
    };
  }, [open, discoveryOnly]);

  useEffect(() => {
    if (!open || discoveryOnly || !engineName) return;
    let cancelled = false;
    // Manual runs use the complete stored catalog. Target profile assignments
    // are scheduling policy and must not narrow this one-off choice.
    fetchProfiles({ kind: "scan", engine: engineName })
      .then((list) => {
        if (cancelled) return;
        setProfiles(list);
        setProfileName((current) =>
          list.some((profile) => profile.name === current)
            ? current
            : (list.find((profile) => profile.name === DEFAULT_PROFILE)?.name ??
              list[0]?.name ??
              DEFAULT_PROFILE),
        );
      })
      .catch((cause) => !cancelled && setError((cause as Error).message));
    return () => {
      cancelled = true;
    };
  }, [open, discoveryOnly, engineName]);

  const selectedEngine = useMemo(
    () => engines.find((engine) => engine.name === engineName) ?? null,
    [engines, engineName],
  );
  const selectedProfile = useMemo(
    () => profiles.find((profile) => profile.name === profileName) ?? null,
    [profiles, profileName],
  );

  useEffect(() => {
    if (!editableProfile || !selectedProfile) {
      setRunConfig(null);
      return;
    }
    setRunConfig(structuredClone(selectedProfile.config));
  }, [editableProfile, selectedProfile]);

  // What this run changes about the scan profile. Sent with the run rather than
  // written back: a one-off custom scan should not redefine what "safe" means
  // for every target that scans with it on a schedule.
  const profileEdits = useMemo(() => {
    if (!runConfig || !selectedProfile) return undefined;
    return sameConfig(runConfig, selectedProfile.config) ? undefined : runConfig;
  }, [runConfig, selectedProfile]);

  // Previewed from the edited config when there is one, so tweaking a profile
  // in the dialog updates what the scan says it will do. Discovery reruns have
  // no scan profile to preview.
  const {
    preview,
    error: previewError,
    loading: previewLoading,
  } = usePreview(
    discoveryOnly ? null : (runConfig ?? selectedProfile?.config ?? null),
    engineName,
  );

  // Follow status while the scanner writes.
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [status?.output]);

  const targets = useMemo(() => {
    const selected = new Set(selectedHosts);
    return !allowAllTargets || scope === "selected"
      ? rows.filter((r) => selected.has(r.host))
      : rows;
  }, [allowAllTargets, rows, selectedHosts, scope]);

  const risky = useMemo(() => {
    const saved = new Set(savedHosts);
    return targets.filter(
      (r) => CONFIRM_CLASSES.has(r.class) || !saved.has(r.host),
    );
  }, [targets, savedHosts]);
  // The server refuses an intrusive scan of these hosts without confirmation,
  // and only an intrusive one. Both halves of that rule are the server's: the
  // profile reports the engine's own verdict, so a safe profile does not ask.
  const needsConfirm =
    !discoveryOnly && risky.length > 0 && selectedProfile?.intrusive === true;

  // Authorisation covers exactly the hosts named in the banner — changing the scope
  // revokes it rather than carrying consent to another run.
  const riskyKey = risky.map((r) => r.host).join(",");
  useEffect(() => setConfirmed(false), [riskyKey, profileName]);

  const classCounts = useMemo(() => {
    const counts = new Map<string, number>();
    targets.forEach((r) => counts.set(r.class, (counts.get(r.class) ?? 0) + 1));
    return [...counts.entries()].sort();
  }, [targets]);

  const sweep = discoveryRunFields(discoveryProfiles);

  const start = useCallback(async () => {
    setStarting(true);
    setError(null);
    try {
      setEditingDiscovery(false);
      if (discoveryOnly) {
        setDiscovering(true);
        setDiscoverResult(
          await runDiscovery({
            host: targets.map((r) => r.host),
            profile: discoveryProfiles.refs,
            ...sweep,
          }),
        );
        return;
      }
      if (editableProfile && !runConfig) {
        setError(`Profile defaults not found: ${profileName}`);
        return;
      }
      // startScan returns the created scan record, not a live status — the
      // running status arrives over the event stream the parent already
      // subscribes to, so there is nothing to hand to onStatus here.
      await startScan({
        target: { host: targets.map((r) => r.host) },
        engine: engineName,
        profile: profileName,
        // Run-only: the profile every other target scans with is left as it
        // is, and "Save as" is how a tweak worth keeping is kept.
        override: profileEdits,
        discoveryProfiles: discoveryProfiles.refs,
        discoveryEngines: sweep.engine,
        discoveryOverride: sweep.override,
        confirm: confirmed,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setStarting(false);
      setDiscovering(false);
    }
  }, [
    sweep,
    discoveryOnly,
    discoveryProfiles,
    targets,
    editableProfile,
    profileEdits,
    runConfig,
    engineName,
    profileName,
    confirmed,
  ]);

  const stop = useCallback(async () => {
    try {
      onStatus(await cancelScan());
    } catch (e) {
      setError((e as Error).message);
    }
  }, [onStatus]);

  // Only a run's progress/findings/log need the tall pinned panel; the setup form alone
  // should size to its content.
  const hasRun = discoveryOnly
    ? discovering || discoverResult !== null
    : !!status && status.phase !== "idle";

  const chooseEngine = (name: string) => {
    setEngineName(name);
    setConfirmed(false);
    setError(null);
  };

  const chooseProfile = (name: string) => {
    setProfileName(name);
    setConfirmed(false);
    setError(null);
  };

  // Keeping a run-only tweak: it becomes a profile of its own rather than
  // redefining the one it was copied from, and this run then uses it.
  const keepAs = async () => {
    if (!selectedProfile || !runConfig) return;
    setKeeping(true);
    setError(null);
    try {
      const created = await saveProfile({
        kind: "scan",
        engine: engineName,
        name: newProfileName,
        config: runConfig,
        comment: selectedProfile.comment,
      });
      setProfiles((current) => [...current, created]);
      setProfileName(created.name);
      setNewProfileName("");
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setKeeping(false);
    }
  };

  const nameTaken = profiles.some(
    (profile) => profile.name === newProfileName,
  );
  const nameable =
    PROFILE_NAME.test(newProfileName) && !nameTaken && profileEdits !== undefined;

  return (
    // The panel is pinned so the findings list and the log own their own scroll
    // regions; Escape is disarmed while a scan is in flight.
    <Modal
      open={open}
      onClose={onClose}
      title={
        discoveryOnly
          ? "Rescan discovery"
          : selectedEngine
            ? `Run ${selectedEngine.title} scan`
            : "Run scan"
      }
      size="xl"
      className={
        editableProfile || editingDiscovery || (hasRun && !discoveryOnly)
          ? "h-[calc(100dvh-4rem)]"
          : undefined
      }
      scrollBody={false}
      closeOnEsc={!controlsLocked}
    >
      <div className="flex min-h-0 flex-1 flex-col gap-3">
        <div className="flex shrink-0 flex-wrap items-end gap-3 rounded-md border border-border bg-muted/30 p-3">
          {allowAllTargets ? (
            <label className="flex flex-col gap-1 text-xs">
              Targets
              <SegmentedControl<Scope>
                size="sm"
                value={scope}
                onChange={setScope}
                options={[
                  {
                    id: "selected",
                    label: `Selected (${selectedHosts.length})`,
                    disabled: selectedHosts.length === 0 || controlsLocked,
                  },
                  {
                    id: "all",
                    label: `All targets (${rows.length})`,
                    disabled: controlsLocked,
                  },
                ]}
              />
            </label>
          ) : (
            <span className="flex flex-col gap-1 text-xs">
              Target
              <code className="h-control-h rounded-md border border-input bg-background px-3 py-2 text-sm">
                {targets[0]?.host}
              </code>
            </span>
          )}
          {!discoveryOnly && (
            <>
              <label className="flex flex-col gap-1 text-xs">
                Engine
                {engines.length > 1 ? (
                  <Select
                    className="w-40"
                    value={engineName}
                    disabled={controlsLocked}
                    options={engines.map((engine) => ({
                      value: engine.name,
                      label: engine.title,
                    }))}
                    onChange={(event) => chooseEngine(event.target.value)}
                  />
                ) : (
                  <span className="h-control-h rounded-md border border-input bg-background px-3 py-2 text-sm">
                    {selectedEngine?.title ?? engineName}
                  </span>
                )}
              </label>
              <label className="flex flex-col gap-1 text-xs">
                Profile
                {profiles.length > 1 ? (
                  <Select
                    className="w-52"
                    value={profileName}
                    disabled={controlsLocked}
                    options={profiles.map((profile) => ({
                      value: profile.name,
                      label: profile.name,
                    }))}
                    onChange={(event) => chooseProfile(event.target.value)}
                  />
                ) : (
                  <span className="h-control-h rounded-md border border-input bg-background px-3 py-2 text-sm">
                    {profileName}
                  </span>
                )}
                {/* Blast radius before the scan starts. A profile name says
                    nothing about how much it checks, and "safe" and "app"
                    differ by four thousand templates. */}
                <TemplateSummary
                  preview={preview}
                  error={previewError}
                  loading={previewLoading}
                />
              </label>
              {/* A run-only tweak is worth keeping often enough that there has
                  to be a way to keep it — and keeping it must not mean writing
                  over the profile it started from. */}
              {editableProfile && profileEdits && (
                <label className="flex flex-col gap-1 text-xs">
                  Keep as profile
                  <span className="flex items-center gap-2">
                    <input
                      value={newProfileName}
                      onChange={(event) =>
                        setNewProfileName(event.target.value)
                      }
                      placeholder="app-deep"
                      aria-label="New scan profile name"
                      disabled={controlsLocked || keeping}
                      className="h-control-h w-40 rounded-md border border-input bg-background px-2 text-sm"
                    />
                    <Button
                      size="sm"
                      variant="outline"
                      loading={keeping}
                      disabled={controlsLocked || keeping || !nameable}
                      onClick={() => void keepAs()}
                    >
                      Save as
                    </Button>
                  </span>
                  <span className="text-muted-foreground">
                    {nameTaken
                      ? `${engineName} already has a profile called "${newProfileName}"`
                      : newProfileName && !PROFILE_NAME.test(newProfileName)
                        ? "Lowercase letters, digits and dashes only"
                        : "This run uses these options either way"}
                  </span>
                </label>
              )}
            </>
          )}
          <span className="flex flex-col gap-1 text-xs">
            Discovery profiles
            <Button
              size="sm"
              variant="outline"
              aria-expanded={editingDiscovery}
              disabled={controlsLocked || !discoveryProfiles.loaded}
              onClick={() => setEditingDiscovery((current) => !current)}
            >
              {editingDiscovery ? "Done editing" : "Edit profiles"}
            </Button>
          </span>
          <span className="flex flex-wrap items-center gap-1 pb-1.5 text-xs text-muted-foreground">
            {classCounts.map(([cls, n]) => (
              <span key={cls} className="rounded bg-muted px-1.5 py-0.5">
                {n} {cls}
              </span>
            ))}
            {describeSelection(discoveryProfiles).map(({ engine, name }) => (
              <span key={engine} className="rounded bg-muted px-1.5 py-0.5">
                {engine} · {name}
              </span>
            ))}
            {discoveryProfiles.edited && (
              <span className="text-amber-600 dark:text-amber-400">
                discovery reconfigured for this run only
              </span>
            )}
          </span>
          <span className="flex-1" />
          {discoveryOnly && discovering ? (
            <Button disabled loading>
              Rescanning…
            </Button>
          ) : (
            <>
              {!discoveryOnly && scanActive && (
                <Button variant="destructive" onClick={() => void stop()}>
                  Cancel active scan
                </Button>
              )}
              <Button
                onClick={() => void start()}
                loading={starting}
                disabled={
                  starting ||
                  targets.length === 0 ||
                  // The run carries the profile's configuration, so it cannot
                  // start before the catalog it is read from has arrived.
                  !catalogLoaded ||
                  (needsConfirm && !confirmed)
                }
              >
                {discoveryOnly
                  ? "Rescan"
                  : scanActive
                    ? "Queue scan"
                    : "Scan"}{" "}
                {targets.length} host
                {targets.length === 1 ? "" : "s"}
              </Button>
            </>
          )}
        </div>

        {needsConfirm && !controlsLocked && (
          <label className="flex shrink-0 items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <span>
              This scan may send <strong>intrusive payloads</strong> at{" "}
              <strong>{risky.length}</strong> prod/public or unsaved host
              {risky.length === 1 ? "" : "s"} (
              {risky.map((r) => r.host).join(", ")}). I authorise this scan.
            </span>
          </label>
        )}

        {error && (
          <p
            className="shrink-0 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-sm text-destructive"
            role="alert"
          >
            {error}
          </p>
        )}

        {editingDiscovery && (
          <DiscoveryProfiles
            state={discoveryProfiles}
            disabled={controlsLocked}
          />
        )}

        {!editingDiscovery &&
          !hasRun &&
          editableProfile &&
          selectedEngine &&
          selectedProfile &&
          runConfig && (
            <ProfileConfig
              engine={selectedEngine}
              profile={selectedProfile}
              value={runConfig}
              onChange={setRunConfig}
              onReset={() =>
                setRunConfig(structuredClone(selectedProfile.config))
              }
              note={`Changes here apply to this scan only — the "${profileName}" profile is left as it is. Use "Save as" to keep them.`}
            />
          )}

        {!discoveryOnly && status && status.phase !== "idle" && (
          <ScanRunStatus
            status={status}
            logRef={logRef}
            onOpenScan={onOpenScan}
          />
        )}

        {discoveryOnly && hasRun && (
          <DiscoveryRunSummary result={discoverResult} running={discovering} />
        )}

        {!hasRun && discoveryOnly && (
          <p className="px-3 pb-2 text-sm text-muted-foreground">
            Re-probes the selected hosts and refreshes their machine-owned
            observation fields — ports, HTTP status, response time, known paths,
            login methods, network, TLS, and technology — without creating scan
            findings.
          </p>
        )}

        {!hasRun && !discoveryOnly && selectedEngine && (
          <p className="px-3 pb-2 text-sm text-muted-foreground">
            Runs {selectedEngine.title} with the "{profileName}" profile over
            the chosen hosts and updates each host's machine-owned scan fields.{" "}
            {selectedEngine.description}
          </p>
        )}
      </div>
    </Modal>
  );
}
