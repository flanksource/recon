import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, SegmentedControl, Select } from "@flanksource/clicky-ui/components";
import { fetchEngines, fetchProfiles, saveProfile } from "./api";
import { overridePatch } from "./api-helpers";
import { EngineConfigForm, sameConfig } from "./EngineConfigForm";
import { profileId } from "./types";
import type { Engine, Profile } from "./types";

// The name every engine falls back to, and the base of the reference list the
// server parses. Engines that need something else are sent as engine=name.
export const BASE_PROFILE = "default";

// Turns the per-engine choices into those references, dropping the ones that
// match the base so the request says only what it changes.
export function profileRefs(
  base: string,
  overrides: Record<string, string>,
): string[] {
  return [
    base,
    ...Object.entries(overrides)
      .filter(([, name]) => name && name !== base)
      .map(([engine, name]) => `${engine}=${name}`)
      .sort(),
  ];
}

type Config = Record<string, unknown>;

export type DiscoveryProfileState = {
  loaded: boolean;
  error: string | null;
  /** Discovery engines that have at least one stored profile. */
  engines: Engine[];
  /** The profile chosen for each engine, keyed by engine name. */
  selection: Record<string, string>;
  choose: (engine: string, name: string) => void;
  profilesFor: (engine: string) => Profile[];
  chosen: (engine: string) => Profile | null;
  draft: (profile: Profile) => Config;
  edit: (profile: Profile, config: Config) => void;
  reset: (profile: Profile) => void;
  /** Whether any engine this run would drive has been reconfigured. */
  edited: boolean;
  /** Whether an engine runs in this sweep. */
  enabled: (engine: string) => boolean;
  toggle: (engine: string) => void;
  /** The engines this sweep drives, in the order the picker lists them. */
  running: string[];
  /**
   * Whether the engine selection still matches what the server would run on its
   * own. A run says nothing about engines while this holds, so the default
   * chain keeps deciding rather than being frozen by whatever was listed today.
   */
  defaultEngines: boolean;
  /** The `profile` references a run should be started with. */
  refs: string[];
  /**
   * The configuration changes this run carries, keyed by engine. Run-only: the
   * stored profile is what the next sweep reads, so a one-off tweak that saved
   * itself would outlive the run it was made for. Promote one with `saveAs`.
   */
  overrides: Record<string, Config>;
  /**
   * Stores the current configuration under a new name for that engine and
   * selects it. Every engine ships one profile, so without this there is never
   * a second one to choose and the per-engine override is unreachable.
   */
  saveAs: (engine: string, name: string) => Promise<void>;
};

// The rule the engine_profiles_name_format constraint enforces, checked here so
// a bad name is refused by the control rather than by the database.
export const PROFILE_NAME = /^[a-z0-9][a-z0-9-]*$/;

// A sweep runs several engines, each with its own stored profile, so choosing
// "the discovery profile" is really choosing one per engine. This owns that
// choice and the unsaved edits made to the chosen profiles.
export function useDiscoveryProfiles(open: boolean): DiscoveryProfileState {
  const [engines, setEngines] = useState<Engine[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [selection, setSelection] = useState<Record<string, string>>({});
  const [running, setRunning] = useState<string[]>([]);
  const [drafts, setDrafts] = useState<Record<string, Config>>({});
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || loaded) return;
    let cancelled = false;
    Promise.all([
      fetchEngines("discovery"),
      fetchProfiles({ kind: "discovery" }),
    ])
      .then(([nextEngines, nextProfiles]) => {
        if (cancelled) return;
        const usable = nextEngines.filter((engine) =>
          nextProfiles.some((profile) => profile.engine === engine.name),
        );
        setProfiles(nextProfiles);
        setEngines(usable);
        setSelection(defaultSelection(nextProfiles));
        // The server says which engines a sweep runs on its own; the picker
        // opens on exactly those rather than on everything registered, so
        // opening the dialog and pressing Run changes nothing.
        setRunning(
          usable.filter((engine) => engine.default).map((engine) => engine.name),
        );
        setDrafts({});
      })
      .catch((cause) => !cancelled && setError((cause as Error).message))
      .finally(() => !cancelled && setLoaded(true));
    return () => {
      cancelled = true;
    };
  }, [open, loaded]);

  useEffect(() => {
    if (!open) setLoaded(false);
  }, [open]);

  const profilesFor = useCallback(
    (engine: string) => profiles.filter((profile) => profile.engine === engine),
    [profiles],
  );

  const chosen = useCallback(
    (engine: string) =>
      profiles.find(
        (profile) =>
          profile.engine === engine && profile.name === selection[engine],
      ) ?? null,
    [profiles, selection],
  );

  const draft = useCallback(
    (profile: Profile) => drafts[profileId(profile)] ?? profile.config,
    [drafts],
  );

  // Only the engines this sweep drives: a tweak to one that was switched off is
  // not carried by the run, and reporting it as an unsaved change would ask
  // about something the sweep will not do.
  const used = useMemo(
    () =>
      engines
        .filter((engine) => running.includes(engine.name))
        .map((engine) => chosen(engine.name))
        .filter((profile): profile is Profile => profile !== null),
    [chosen, engines, running],
  );

  const editedProfiles = useMemo(
    () => used.filter((profile) => !sameConfig(draft(profile), profile.config)),
    [draft, used],
  );

  const overrides = useMemo(() => {
    const changed: Record<string, Config> = {};
    for (const profile of editedProfiles) {
      changed[profile.engine] = overridePatch(profile.config, draft(profile));
    }
    return changed;
  }, [draft, editedProfiles]);

  const saveAs = useCallback(
    async (engine: string, name: string) => {
      const source = chosen(engine);
      if (!source) throw new Error(`no profile is selected for ${engine}`);
      const created = await saveProfile({
        kind: source.kind,
        engine,
        name,
        config: draft(source),
        comment: source.comment,
      });
      setProfiles((current) => [...current, created]);
      // The tweak now lives in the new profile, so the one it was copied from
      // must stop looking edited — otherwise starting the run would write these
      // changes back over it as well.
      setDrafts((current) => {
        const next = { ...current };
        delete next[profileId(source)];
        return next;
      });
      setSelection((current) => ({ ...current, [engine]: created.name }));
    },
    [chosen, draft],
  );

  return {
    loaded,
    error,
    engines,
    selection,
    choose: (engine, name) =>
      setSelection((current) => ({ ...current, [engine]: name })),
    profilesFor,
    chosen,
    draft,
    edit: (profile, config) =>
      setDrafts((current) => ({ ...current, [profileId(profile)]: config })),
    reset: (profile) =>
      setDrafts((current) => {
        const next = { ...current };
        delete next[profileId(profile)];
        return next;
      }),
    edited: editedProfiles.length > 0,
    enabled: (engine) => running.includes(engine),
    toggle: (engine) =>
      setRunning((current) =>
        current.includes(engine)
          ? current.filter((name) => name !== engine)
          : [...current, engine],
      ),
    running,
    defaultEngines: sameEngines(
      running,
      engines.filter((engine) => engine.default).map((engine) => engine.name),
    ),
    refs: profileRefs(BASE_PROFILE, selection),
    overrides,
    saveAs,
  };
}

// Order is not part of the choice — the server derives a sweep's order from what
// each engine consumes — so two selections holding the same engines are the
// same selection however the picker listed them.
function sameEngines(left: string[], right: string[]): boolean {
  return (
    left.length === right.length && [...left].sort().join() === [...right].sort().join()
  );
}

// Every engine starts on the base profile. An engine that does not have one is
// pinned to its first stored profile instead of being left unset — the run
// would fail on a profile that is not there, and the picker is where that has
// to be visible.
function defaultSelection(profiles: Profile[]): Record<string, string> {
  const selection: Record<string, string> = {};
  for (const profile of profiles) {
    const current = selection[profile.engine];
    if (current === BASE_PROFILE) continue;
    if (current === undefined || profile.name === BASE_PROFILE) {
      selection[profile.engine] = profile.name;
    }
  }
  return selection;
}

// The engine and configuration a run should carry, with the fields that say
// nothing left out entirely.
//
// Absent is not the same as empty here: while no engine has been deselected the
// request names none, and the server's own chain keeps deciding — sending
// today's list instead would freeze a targeted sweep to the engines a full one
// happens to run.
export function discoveryRunFields(state: DiscoveryProfileState): {
  engine?: string[];
  override?: Record<string, Config>;
} {
  return {
    ...(state.defaultEngines ? {} : { engine: state.running }),
    ...(Object.keys(state.overrides).length > 0
      ? { override: state.overrides }
      : {}),
  };
}

/** One line naming the profile each engine this sweep drives will run with. */
export function describeSelection(
  state: DiscoveryProfileState,
): { engine: string; name: string }[] {
  return state.engines
    .filter((engine) => state.enabled(engine.name))
    .map((engine) => ({
      engine: engine.title,
      name: state.selection[engine.name] ?? BASE_PROFILE,
    }));
}

export function DiscoveryProfiles({
  state,
  disabled,
}: {
  state: DiscoveryProfileState;
  disabled?: boolean;
}) {
  const [engineName, setEngineName] = useState("");
  const [newName, setNewName] = useState("");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const active =
    state.engines.find((engine) => engine.name === engineName) ??
    state.engines[0];
  const profile = active ? state.chosen(active.name) : null;

  const taken = active
    ? state.profilesFor(active.name).some((option) => option.name === newName)
    : false;
  const nameable = PROFILE_NAME.test(newName) && !taken;

  const chooseEngine = (name: string) => {
    setEngineName(name);
    setNewName("");
    setSaveError(null);
  };

  const saveAs = async () => {
    if (!active) return;
    setSaving(true);
    setSaveError(null);
    try {
      await state.saveAs(active.name, newName);
      setNewName("");
    } catch (cause) {
      setSaveError((cause as Error).message);
    } finally {
      setSaving(false);
    }
  };

  if (!state.loaded) {
    return (
      <div className="flex min-h-0 flex-1 items-center justify-center rounded-md border border-border p-6 text-sm text-muted-foreground">
        Loading discovery profiles…
      </div>
    );
  }
  if (!active || !profile) {
    return (
      <div className="flex min-h-0 flex-1 items-center justify-center rounded-md border border-border p-6 text-sm text-muted-foreground">
        No discovery profiles are stored.
      </div>
    );
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      {/* Which engines run, before which profile each runs with: a sweep that
          skips the port scan is a different sweep, not a differently
          configured one. */}
      <fieldset className="flex shrink-0 flex-wrap items-center gap-3 rounded-md border border-border p-2">
        <legend className="px-1 text-xs text-muted-foreground">
          Engines in this sweep
        </legend>
        {state.engines.map((engine) => (
          <label
            key={engine.name}
            className="flex items-center gap-1.5 text-xs"
            title={
              engine.accepts && engine.emits
                ? `${engine.accepts} → ${engine.emits}`
                : undefined
            }
          >
            <input
              type="checkbox"
              checked={state.enabled(engine.name)}
              disabled={disabled}
              onChange={() => state.toggle(engine.name)}
            />
            {engine.title}
            {!engine.default && (
              <span className="text-muted-foreground">(off by default)</span>
            )}
          </label>
        ))}
        {state.running.length === 0 && (
          <span className="text-destructive">
            A sweep with no engines observes nothing.
          </span>
        )}
      </fieldset>

      <div className="flex shrink-0 flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs">
          Engine
          <SegmentedControl<string>
            size="sm"
            value={active.name}
            onChange={chooseEngine}
            options={state.engines.map((engine) => ({
              id: engine.name,
              label: state.enabled(engine.name)
                ? `${engine.title} · ${state.selection[engine.name] ?? BASE_PROFILE}`
                : `${engine.title} · not running`,
              disabled,
            }))}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          Profile
          <Select
            className="w-52"
            aria-label={`${active.title} profile`}
            value={profile.name}
            disabled={disabled}
            options={state
              .profilesFor(active.name)
              .map((option) => ({ value: option.name, label: option.name }))}
            onChange={(event) => state.choose(active.name, event.target.value)}
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          New profile
          <input
            value={newName}
            onChange={(event) => setNewName(event.target.value)}
            placeholder="full-ports"
            disabled={disabled || saving}
            className="h-control-h w-44 rounded-md border border-input bg-background px-2 text-sm"
          />
        </label>
        <Button
          size="sm"
          variant="outline"
          loading={saving}
          disabled={disabled || saving || !nameable}
          onClick={() => void saveAs()}
        >
          Save as
        </Button>
        <span className="pb-1.5 text-xs text-muted-foreground">
          {saveError ? (
            <span className="text-destructive">{saveError}</span>
          ) : taken ? (
            `${active.title} already has a profile called "${newName}"`
          ) : newName && !nameable ? (
            "Lowercase letters, digits and dashes only"
          ) : (
            `Keeps these options as a new ${active.title} profile and runs this sweep with it`
          )}
        </span>
      </div>

      <EngineConfigForm
        key={profileId(profile)}
        engine={active}
        identity={profileId(profile)}
        value={state.draft(profile)}
        baseline={profile.config}
        onChange={(config) => state.edit(profile, config)}
        onReset={() => state.reset(profile)}
        note={
          state.enabled(active.name)
            ? `Changes here apply to this sweep only — the "${profile.name}" ${active.title} profile is left as it is. Use "Save as" to keep them.`
            : `${active.title} is not running in this sweep, so these options will not be used.`
        }
      />
    </div>
  );
}
