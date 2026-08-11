import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, JsonSchemaForm } from "@flanksource/clicky-ui";
import { sameConfig, sectionSchema } from "./ProfileConfig";
import { useProfileFilterPairs } from "./ProfileFilterPairs";
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
  const [sectionId, setSectionId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { pre, post, hiddenKeys } = useProfileFilterPairs();

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

  const selected = useMemo(
    () => profiles.find((profile) => profileId(profile) === selectedId) ?? null,
    [profiles, selectedId],
  );
  const sections = useMemo(
    () => (selected ? (engines.find((engine) => engine.name === selected.engine)?.sections ?? []) : []),
    [selected, engines],
  );
  const activeSection =
    sections.find((section) => section.id === sectionId) ?? sections[0];
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
    selected && selected.kind === "scan" ? draft : null,
    selected?.engine ?? "nuclei",
  );

  const selectProfile = (profile: Profile) => {
    setSelectedId(profileId(profile));
    setSectionId(null);
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
        <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto p-3">
          {profiles.map((profile) => (
            <button
              key={profileId(profile)}
              type="button"
              aria-label={`${profile.name} ${engineTitle(profile.engine)}`}
              onClick={() => selectProfile(profile)}
              className={`rounded-md border p-3 text-left transition-colors ${
                selected && profileId(selected) === profileId(profile)
                  ? "border-primary bg-primary/5"
                  : "border-border bg-background hover:bg-accent"
              }`}
            >
              <span className="flex items-center gap-2">
                <span className="font-medium">{profile.name}</span>
                <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                  {engineTitle(profile.engine)}
                </span>
                {!sameConfig(
                  drafts[profileId(profile)] ?? profile.config,
                  profile.config,
                ) && (
                  <span
                    className="ml-auto h-2 w-2 rounded-full bg-amber-500"
                    title="Unsaved changes"
                  />
                )}
              </span>
              <code className="mt-1 block text-[11px] text-muted-foreground">
                {profileId(profile)}
              </code>
            </button>
          ))}
          {!busy && profiles.length === 0 && (
            <p className="text-sm text-muted-foreground">No profiles found.</p>
          )}
        </div>
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

        {selected && activeSection && (
          <div className="flex min-h-0 flex-1">
            <nav className="w-56 shrink-0 space-y-1 overflow-y-auto border-r border-border p-3">
              {sections.map((section) => (
                <button
                  key={section.id}
                  type="button"
                  onClick={() => setSectionId(section.id)}
                  className={`w-full rounded-md px-3 py-2 text-left text-sm transition-colors ${
                    section.id === activeSection.id
                      ? "bg-accent font-medium text-accent-foreground"
                      : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
                  }`}
                >
                  {section.title}
                </button>
              ))}
            </nav>

            <main className="min-w-0 flex-1 overflow-y-auto p-5">
              <div className="mb-5 max-w-4xl">
                <div className="flex items-start gap-3">
                  <div>
                    <h3 className="text-lg font-semibold">
                      {activeSection.title}
                    </h3>
                    <p className="mt-1 text-sm text-muted-foreground">
                      {activeSection.description}
                    </p>
                  </div>
                  {activeSection.sourceUrl && (
                    <a
                      href={activeSection.sourceUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="ml-auto shrink-0 text-xs text-primary hover:underline"
                    >
                      Upstream flags ↗
                    </a>
                  )}
                </div>
              </div>
              <div className="max-w-6xl rounded-lg border border-border bg-background p-5 shadow-sm">
                <JsonSchemaForm
                  key={`${profileId(selected)}:${activeSection.id}`}
                  idPrefix={`${selected.engine}-${selected.name}-${activeSection.id}`}
                  schema={sectionSchema(activeSection)}
                  value={draft}
                  onChange={(next) =>
                    setDrafts((current) => ({
                      ...current,
                      [profileId(selected)]: next,
                    }))
                  }
                  pre={pre}
                  post={post}
                  hiddenKeys={hiddenKeys}
                  layout={{
                    mode: "stacked",
                    help: "hover",
                    valueMaxWidth: "100%",
                  }}
                  size="sm"
                  preferencesStorageKey="nuclei-profile-form-preferences"
                />
              </div>
              <p className="mt-4 max-w-4xl text-xs text-muted-foreground">
                Profile changes are saved to the server. Keep credentials,
                bearer tokens, and private keys in external secret files
                rather than these fields.
              </p>
            </main>

            {/* The form describes the configuration; this says what it does.
                Without it the only way to learn what a tag change selected was
                to save the profile and run a scan. */}
            {selected.kind === "scan" && (
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
                    onBrowseTemplates ? () => onBrowseTemplates(selected.name) : undefined
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
