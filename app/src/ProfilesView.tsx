import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { EngineConfigForm, sameConfig } from "./EngineConfigForm";
import { ProfileTree } from "./ProfileTree";
import { TemplatePreviewPanel, usePreview } from "./TemplatePreview";
import { fetchEngines, fetchProfiles, saveProfile } from "./api";
import { profileId } from "./types";
import type { Engine, Profile } from "./types";

type Props = {
  /** Opens the template browser scoped to a profile. */
  onBrowseTemplates?: (profile: string) => void;
};

export function ProfilesView({ onBrowseTemplates }: Props = {}) {
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [engines, setEngines] = useState<Engine[]>([]);
  const [drafts, setDrafts] = useState<Record<string, Record<string, unknown>>>(
    {},
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const [nextProfiles, nextEngines] = await Promise.all([
        fetchProfiles(),
        fetchEngines(),
      ]);
      setProfiles(nextProfiles);
      setEngines(nextEngines);
      setDrafts(
        Object.fromEntries(nextProfiles.map((profile) => [profileId(profile), profile.config])),
      );
      setSelectedId((current) =>
        current && nextProfiles.some((profile) => profileId(profile) === current)
          ? current
          : (nextProfiles[0] ? profileId(nextProfiles[0]) : null),
      );
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const engineTitle = useCallback(
    (name: string) => engines.find((engine) => engine.name === name)?.title ?? name,
    [engines],
  );
  const providerTitle = useCallback(
    (engineName: string, provider: string) => {
      const title = engines
        .find((engine) => engine.name === engineName)
        ?.options.variants.find((variant) => variant.id === provider)?.title;
      if (!title) {
        throw new Error(`${engineName} does not define provider variant "${provider}"`);
      }
      return title;
    },
    [engines],
  );

  const selected = useMemo(
    () => profiles.find((profile) => profileId(profile) === selectedId) ?? null,
    [profiles, selectedId],
  );
  const selectedEngine = useMemo(
    () =>
      selected
        ? (engines.find((engine) => engine.name === selected.engine) ?? null)
        : null,
    [selected, engines],
  );
  const draft = selected ? (drafts[profileId(selected)] ?? selected.config) : {};
  const dirty = selected ? !sameConfig(draft, selected.config) : false;

  // Previewed from the draft rather than the stored profile: the question being
  // asked is what the edit in front of you would run, not what the last save
  // did. Discovery profiles have no template catalogue, so they get no preview.
  const {
    preview,
    error: previewError,
    loading: previewLoading,
  } = usePreview(
    selected?.engine === "nuclei" ? draft : null,
    selected?.engine ?? "nuclei",
  );

  const selectProfile = (profile: Profile) => {
    setSelectedId(profileId(profile));
  };

  const reloadSelected = () => {
    if (!selected) return;
    setDrafts((current) => ({ ...current, [profileId(selected)]: selected.config }));
  };

  const saveSelected = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await saveProfile({
        kind: selected.kind,
        engine: selected.engine,
        name: selected.name,
        config: draft,
        comment: selected.comment,
      });
      setProfiles((current) =>
        current.map((profile) => (profileId(profile) === profileId(saved) ? saved : profile)),
      );
      setDrafts((current) => ({ ...current, [profileId(saved)]: saved.config }));
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full min-h-0 bg-background text-foreground">
      <aside className="flex w-72 shrink-0 flex-col border-r border-border bg-muted/20">
        <div className="border-b border-border px-4 py-3">
          <h1 className="text-lg font-semibold">Profiles</h1>
          <p className="mt-1 text-xs text-muted-foreground">
            Schema-driven scan and discovery configuration
          </p>
        </div>
        {!busy || profiles.length > 0 ? (
          <ProfileTree
            profiles={profiles}
            selectedId={selectedId}
            engineTitle={engineTitle}
            providerTitle={providerTitle}
            isDirty={(profile) =>
              !sameConfig(
                drafts[profileId(profile)] ?? profile.config,
                profile.config,
              )
            }
            onSelect={selectProfile}
          />
        ) : null}
      </aside>

      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-border px-5 py-3">
          {selected ? (
            <>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-base font-semibold">{selected.name}</h2>
                  <span className="text-xs text-muted-foreground">
                    {engineTitle(selected.engine)} profile
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">{profileId(selected)}</p>
              </div>
              <span className="flex-1" />
              {error && (
                <span role="alert" className="text-sm text-destructive">
                  {error}
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
                onClick={reloadSelected}
                disabled={busy || !dirty}
              >
                Revert
              </Button>
              <Button
                size="sm"
                onClick={() => void saveSelected()}
                disabled={busy || !dirty}
                loading={busy}
              >
                Save profile
              </Button>
            </>
          ) : (
            <span className="text-sm text-muted-foreground">
              Select a profile
            </span>
          )}
        </header>

        {selected && selectedEngine && (
          <div className="flex min-h-0 flex-1">
            <main className="min-w-0 flex-1 overflow-y-auto p-5">
              <EngineConfigForm
                engine={selectedEngine}
                identity={profileId(selected)}
                value={draft}
                onChange={(next) =>
                  setDrafts((current) => ({
                    ...current,
                    [profileId(selected)]: next,
                  }))
                }
                note="Profile changes are saved to the server. Keep credentials, bearer tokens, and private keys in external secret files rather than these fields."
                preferencesStorageKey="engine-profile-form-preferences"
              />
            </main>

            {/* The form describes the configuration; this says what it does.
                Without it the only way to learn what a tag change selected was
                to save the profile and run a scan. */}
            {selected.engine === "nuclei" && (
              <aside
                aria-label="Templates this profile runs"
                className="w-80 shrink-0 overflow-y-auto border-l border-border bg-muted/20 p-4"
              >
                <h3 className="mb-3 text-sm font-semibold">This profile runs</h3>
                <TemplatePreviewPanel
                  preview={preview}
                  error={previewError}
                  loading={previewLoading}
                  onBrowse={
                    onBrowseTemplates ? () => onBrowseTemplates(profileId(selected)) : undefined
                  }
                />
              </aside>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
