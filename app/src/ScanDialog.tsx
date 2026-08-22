import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Modal } from "@flanksource/clicky-ui/components";
import {
  cancelScan,
  fetchEngines,
  fetchProfiles,
  runDiscovery,
  saveProfile,
  startScan,
} from "./api";
import { EngineConfigForm, sameConfig } from "./EngineConfigForm";
import {
  DiscoveryProfiles,
  PROFILE_NAME,
  discoveryRunFields,
  useDiscoveryProfiles,
} from "./DiscoveryProfiles";
import { DiscoveryRunSummary } from "./DiscoveryRunSummary";
import { ScanDialogSetup } from "./ScanDialogSetup";
import { ScanRunStatus } from "./ScanRunStatus";
import { usePreview } from "./TemplatePreview";
import {
  CONFIRM_CLASSES,
  DEFAULT_ENGINE,
  DEFAULT_PROFILE,
  parseProfileRef,
  type ScanDialogProps,
  type ScanScope,
} from "./scan-dialog-model";
import { profileId, targetHost, targetId, targetKind } from "./types";
import type { Discover, Engine, Profile } from "./types";

export function ScanDialog({
  open,
  onClose,
  rows,
  savedTargetIds,
  selectedTargetIds,
  status,
  onStatus,
  onOpenScan,
  allowAllTargets = true,
  discoveryOnly = false,
  editableProfile = true,
  preferredProfile,
}: ScanDialogProps) {
  const preferred = preferredProfile ? parseProfileRef(preferredProfile) : null;
  const [scope, setScope] = useState<ScanScope>("selected");
  const [engines, setEngines] = useState<Engine[]>([]);
  const [engineName, setEngineName] = useState(preferred?.engine ?? DEFAULT_ENGINE);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profileName, setProfileName] = useState(preferred?.profile ?? DEFAULT_PROFILE);
  const [runConfig, setRunConfig] = useState<Record<string, unknown> | null>(
    null,
  );
  const [newProfileName, setNewProfileName] = useState("");
  const [keeping, setKeeping] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  // Off by default: the rules exist because someone accepted those findings,
  // and a run that quietly ignored them would report work already triaged.
  const [ignoreMutes, setIgnoreMutes] = useState(false);
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
    setScope(selectedTargetIds.length ? "selected" : "all");
    if (preferred) {
      setEngineName(preferred.engine);
      setProfileName(preferred.profile);
    }
  }, [open, preferred?.engine, preferred?.profile, selectedTargetIds.length]);

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
        // The engine's own default first: "safe" is nuclei's name for it and
        // means nothing to a compliance engine, so preferring it would open
        // the picker on whichever profile happened to sort first.
        const preferred =
          engines.find((engine) => engine.name === engineName)?.defaults ??
          DEFAULT_PROFILE;
        setProfileName((current) =>
          list.some((profile) => profile.name === current)
            ? current
            : (list.find((profile) => profile.name === preferred)?.name ??
              list[0]?.name ??
              preferred),
        );
      })
      .catch((cause) => !cancelled && setError((cause as Error).message));
    return () => {
      cancelled = true;
    };
  }, [open, discoveryOnly, engineName, engines]);

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
    discoveryOnly || engineName !== "nuclei"
      ? null
      : (runConfig ?? selectedProfile?.config ?? null),
    engineName,
  );

  // Follow status while the scanner writes.
  useEffect(() => {
    const el = logRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [status?.output]);

  const targets = useMemo(() => {
    const selected = new Set(selectedTargetIds);
    return !allowAllTargets || scope === "selected"
      ? rows.filter((r) => selected.has(targetId(r)))
      : rows;
  }, [allowAllTargets, rows, selectedTargetIds, scope]);
  const targetNoun = targets.every((target) => targetKind(target) === "host")
    ? "host"
    : "target";

  const risky = useMemo(() => {
    const saved = new Set(savedTargetIds);
    return targets.filter(
      (r) => CONFIRM_CLASSES.has(r.class) || !saved.has(targetId(r)),
    );
  }, [targets, savedTargetIds]);
  // The server refuses an intrusive scan of these hosts without confirmation,
  // and only an intrusive one. Both halves of that rule are the server's: the
  // profile reports the engine's own verdict, so a safe profile does not ask.
  const needsConfirm =
    !discoveryOnly && risky.length > 0 && selectedProfile?.intrusive === true;

  // Authorisation covers exactly the hosts named in the banner — changing the scope
  // revokes it rather than carrying consent to another run.
  const riskyKey = risky.map(targetId).join(",");
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
            host: targets
              .filter((target) => targetKind(target) === "host")
              .map(targetHost),
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
        target: { id: targets.map(targetId) },
        engine: engineName,
        profile: profileName,
        // Run-only: the profile every other target scans with is left as it
        // is, and "Save as" is how a tweak worth keeping is kept.
        override: profileEdits,
        discoveryProfiles: discoveryProfiles.refs,
        discoveryEngines: sweep.engine,
        discoveryOverride: sweep.override,
        confirm: confirmed,
        noMutes: ignoreMutes,
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
    ignoreMutes,
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
        <ScanDialogSetup
          selection={{
            allowAllTargets,
            scope,
            selectedCount: selectedTargetIds.length,
            rowCount: rows.length,
            targetId: targets[0] ? targetId(targets[0]) : "",
            onScopeChange: setScope,
          }}
          scanner={
            discoveryOnly
              ? undefined
              : {
                  engines,
                  engineName,
                  selectedEngine,
                  profiles,
                  profileName,
                  editableProfile,
                  profileEdits,
                  preview,
                  previewError,
                  previewLoading,
                  newProfileName,
                  nameTaken,
                  nameable,
                  keeping,
                  onChooseEngine: chooseEngine,
                  onChooseProfile: chooseProfile,
                  onNewProfileName: setNewProfileName,
                  onKeepAs: () => void keepAs(),
                }
          }
          discovery={{
            profiles: discoveryProfiles,
            editing: editingDiscovery,
            onEditingChange: setEditingDiscovery,
          }}
          action={{
            discoveryOnly,
            discovering,
            scanActive,
            starting,
            catalogLoaded,
            targetCount: targets.length,
            targetNoun,
            needsConfirm,
            confirmed,
            onStart: () => void start(),
            onStop: () => void stop(),
          }}
          classCounts={classCounts}
          controlsLocked={controlsLocked}
          mutes={
            discoveryOnly
              ? undefined
              : { ignored: ignoreMutes, onIgnoredChange: setIgnoreMutes }
          }
          confirmation={
            needsConfirm
              ? {
                  targetIds: risky.map(targetId),
                  confirmed,
                  onConfirmedChange: setConfirmed,
                }
              : undefined
          }
        />

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
            <EngineConfigForm
              engine={selectedEngine}
              identity={profileId(selectedProfile)}
              value={runConfig}
              baseline={selectedProfile.config}
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
            the chosen targets and updates their machine-owned scan fields.{" "}
            {selectedEngine.description}
          </p>
        )}
      </div>
    </Modal>
  );
}
