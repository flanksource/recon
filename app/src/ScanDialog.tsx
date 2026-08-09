import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Button, Modal, SegmentedControl, Select } from "@flanksource/clicky-ui";
import { cancelScan, startScan } from "./api";
import { ScanProfileConfig } from "./ScanProfileConfig";
import { ScanRunStatus } from "./ScanRunStatus";
import {
  SCAN_PROFILES,
  type ScanProfile,
  type ScanStatus,
  type ProfileDocument,
  type TargetRow,
} from "./types";

// Classes where a full/DAST run would send malicious payloads at something real —
// same gate the server enforces and `task scan:full` enforces on the CLI. A host not yet
// written to the inventory is treated the same way: the server cannot verify its class,
// so an unsaved "non-prod" is not proof of anything.
const CONFIRM_CLASSES = new Set(["prod", "public"]);

const PROFILE_LABELS: Record<string, string> = {
  safe: "safe (non-intrusive)",
  full: "full (DAST)",
  discovery: "discovery (Naabu + httpx)",
};
const EMPTY_PROFILES: ProfileDocument[] = [];

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
  onOpenScan?: (file: string) => void;
  availableProfiles?: readonly ScanProfile[];
  initialProfile?: ScanProfile;
  allowAllTargets?: boolean;
  nucleiProfiles?: ProfileDocument[];
  editableNucleiProfile?: boolean;
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
  availableProfiles = SCAN_PROFILES,
  initialProfile,
  allowAllTargets = true,
  nucleiProfiles = EMPTY_PROFILES,
  editableNucleiProfile = false,
}: Props) {
  const defaultProfile = initialProfile ?? availableProfiles[0];
  if (!defaultProfile)
    throw new Error("ScanDialog requires at least one profile");
  const [scope, setScope] = useState<Scope>("selected");
  const [profile, setProfile] = useState<ScanProfile>(defaultProfile);
  const [runConfig, setRunConfig] = useState<Record<string, unknown> | null>(
    null,
  );
  const [confirmed, setConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const running = status?.phase === "running";

  // Scope defaults on open only. Re-deriving it while the dialog is open would silently
  // widen a run to every target if the selection changed underneath it.
  const selectionCount = useRef(selectedHosts.length);
  selectionCount.current = selectedHosts.length;
  useEffect(() => {
    if (!open) return;
    setError(null);
    setScope(selectionCount.current ? "selected" : "all");
    setProfile(defaultProfile);
    if (editableNucleiProfile) {
      const defaults = nucleiProfiles.find(
        (candidate) =>
          candidate.engine === "nuclei" && candidate.name === defaultProfile,
      );
      if (!defaults) {
        setRunConfig(null);
        setError(`Nuclei profile defaults not found: ${defaultProfile}`);
        return;
      }
      setRunConfig(structuredClone(defaults.config));
    }
  }, [open, defaultProfile, editableNucleiProfile, nucleiProfiles]);

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
  const unsaved = useMemo(() => {
    const saved = new Set(savedHosts);
    return targets.filter((target) => !saved.has(target.host));
  }, [savedHosts, targets]);
  const needsConfirm =
    (editableNucleiProfile ? runConfig?.dast === true : profile === "full") &&
    risky.length > 0;
  const needsSavedTargets = profile === "discovery" && unsaved.length > 0;

  // Authorisation covers exactly the hosts named in the banner — changing the scope or
  // effective configuration revokes it rather than carrying consent to another run.
  const riskyKey = risky.map((r) => r.host).join(",");
  const configKey = editableNucleiProfile ? JSON.stringify(runConfig) : "";
  useEffect(() => setConfirmed(false), [riskyKey, profile, configKey]);

  const classCounts = useMemo(() => {
    const counts = new Map<string, number>();
    targets.forEach((r) => counts.set(r.class, (counts.get(r.class) ?? 0) + 1));
    return [...counts.entries()].sort();
  }, [targets]);

  const start = useCallback(async () => {
    if (editableNucleiProfile && !runConfig) {
      setError(`Nuclei profile defaults not found: ${profile}`);
      return;
    }
    setStarting(true);
    setError(null);
    try {
      onStatus(
        await startScan({
          hosts: targets.map((r) => r.host),
          profile,
          confirm: confirmed,
          config: editableNucleiProfile ? runConfig ?? undefined : undefined,
        }),
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setStarting(false);
    }
  }, [
    targets,
    profile,
    confirmed,
    editableNucleiProfile,
    runConfig,
    onStatus,
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
  const hasRun = !!status && status.phase !== "idle";
  const discoveryRun = status?.profile === "discovery";
  const discoveryOnly =
    availableProfiles.length === 1 && availableProfiles[0] === "discovery";
  const selectedNucleiProfile = nucleiProfiles.find(
    (candidate) =>
      candidate.engine === "nuclei" && candidate.name === profile,
  );

  const chooseProfile = (nextProfile: ScanProfile) => {
    setProfile(nextProfile);
    setConfirmed(false);
    setError(null);
    if (!editableNucleiProfile) return;
    const defaults = nucleiProfiles.find(
      (candidate) =>
        candidate.engine === "nuclei" && candidate.name === nextProfile,
    );
    if (!defaults) {
      setRunConfig(null);
      setError(`Nuclei profile defaults not found: ${nextProfile}`);
      return;
    }
    setRunConfig(structuredClone(defaults.config));
  };

  return (
    // The panel is pinned so the findings list and the log own their own scroll
    // regions; Escape is disarmed while a scan is in flight.
    <Modal
      open={open}
      onClose={onClose}
      title={
        discoveryOnly
          ? "Rescan discovery"
          : editableNucleiProfile
            ? "Run Nuclei scan"
            : "Run scan"
      }
      size="xl"
      className={
        editableNucleiProfile || (hasRun && !discoveryRun)
          ? "h-[calc(100dvh-4rem)]"
          : undefined
      }
      scrollBody={false}
      closeOnEsc={!running}
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
                    disabled: selectedHosts.length === 0 || running,
                  },
                  {
                    id: "all",
                    label: `All targets (${rows.length})`,
                    disabled: running,
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
          <label className="flex flex-col gap-1 text-xs">
            {editableNucleiProfile ? "Profile defaults" : "Profile"}
            {availableProfiles.length > 1 ? (
              <Select
                className="w-52"
                value={profile}
                disabled={running}
                options={availableProfiles.map((value) => ({
                  value,
                  label: PROFILE_LABELS[value] ?? value,
                }))}
                onChange={(event) => chooseProfile(event.target.value)}
              />
            ) : (
              <span className="h-control-h rounded-md border border-input bg-background px-3 py-2 text-sm">
                {PROFILE_LABELS[profile] ?? profile}
              </span>
            )}
          </label>
          <span className="flex flex-wrap items-center gap-1 pb-1.5 text-xs text-muted-foreground">
            {classCounts.map(([cls, n]) => (
              <span key={cls} className="rounded bg-muted px-1.5 py-0.5">
                {n} {cls}
              </span>
            ))}
          </span>
          <span className="flex-1" />
          {running ? (
            <Button variant="destructive" onClick={() => void stop()}>
              Cancel scan
            </Button>
          ) : (
            <Button
              onClick={() => void start()}
              loading={starting}
              disabled={
                starting ||
                targets.length === 0 ||
                needsSavedTargets ||
                (needsConfirm && !confirmed)
              }
            >
              {profile === "discovery" ? "Rescan" : "Scan"} {targets.length}{" "}
              host
              {targets.length === 1 ? "" : "s"}
            </Button>
          )}
        </div>

        {needsConfirm && !running && (
          <label className="flex shrink-0 items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
            />
            <span>
              This configuration sends <strong>DAST/fuzzing payloads</strong> at{" "}
              <strong>{risky.length}</strong> prod/public or unsaved host
              {risky.length === 1 ? "" : "s"} (
              {risky.map((r) => r.host).join(", ")}). I authorise this scan.
            </span>
          </label>
        )}

        {needsSavedTargets && !running && (
          <p className="shrink-0 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm text-amber-800 dark:text-amber-200">
            Save {unsaved.length} new target{unsaved.length === 1 ? "" : "s"}{" "}
            before rescanning discovery observations.
          </p>
        )}

        {error && (
          <p
            className="shrink-0 rounded-md border border-destructive/40 bg-destructive/10 p-2 text-sm text-destructive"
            role="alert"
          >
            {error}
          </p>
        )}

        {!hasRun &&
          editableNucleiProfile &&
          selectedNucleiProfile &&
          runConfig && (
            <ScanProfileConfig
              profile={selectedNucleiProfile}
              value={runConfig}
              onChange={setRunConfig}
              onReset={() =>
                setRunConfig(structuredClone(selectedNucleiProfile.config))
              }
            />
          )}

        {status && status.phase !== "idle" && (
          <ScanRunStatus
            status={status}
            logRef={logRef}
            onOpenScan={onOpenScan}
          />
        )}

        {!hasRun && profile === "discovery" && (
          <p className="px-3 pb-2 text-sm text-muted-foreground">
            Runs Naabu with <code>config/discovery.naabu.yaml</code>, then probes
            open endpoints and known login paths with httpx. It refreshes
            machine-owned ports, HTTP status, response time, paths, login
            methods, network, TLS, and technology observations without creating
            Nuclei findings.
          </p>
        )}

        {!hasRun && profile !== "discovery" && !editableNucleiProfile && (
          <p className="px-3 pb-2 text-sm text-muted-foreground">
            Runs the same nuclei command as <code>task scan:{profile}</code>{" "}
            over the chosen hosts, writes <code>results/*.jsonl</code>, and
            updates each host's machine-owned scan fields in its inventory
            document.
          </p>
        )}
      </div>
    </Modal>
  );
}
