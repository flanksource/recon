import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, JsonSchemaForm } from "@flanksource/clicky-ui";
import { profileSections, sectionSchema } from "../profile-schema/index.ts";
import { fetchProfiles, saveProfile } from "./api";
import type { ProfileDocument } from "./types";

function sameConfig(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function engineLabel(profile: ProfileDocument): string {
  if (profile.engine === "nuclei") return "Nuclei";
  if (profile.engine === "naabu") return "Naabu";
  return "httpx";
}

export function ProfilesView() {
  const [profiles, setProfiles] = useState<ProfileDocument[]>([]);
  const [drafts, setDrafts] = useState<Record<string, Record<string, unknown>>>(
    {},
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [sectionId, setSectionId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const next = await fetchProfiles();
      setProfiles(next);
      setDrafts(
        Object.fromEntries(next.map((profile) => [profile.id, profile.config])),
      );
      setSelectedId((current) =>
        current && next.some((profile) => profile.id === current)
          ? current
          : (next[0]?.id ?? null),
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

  const selected = useMemo(
    () => profiles.find((profile) => profile.id === selectedId) ?? null,
    [profiles, selectedId],
  );
  const sections = selected ? profileSections[selected.engine] : [];
  const activeSection =
    sections.find((section) => section.id === sectionId) ?? sections[0];
  const draft = selected ? (drafts[selected.id] ?? selected.config) : {};
  const dirty = selected ? !sameConfig(draft, selected.config) : false;

  const selectProfile = (profile: ProfileDocument) => {
    setSelectedId(profile.id);
    setSectionId(null);
  };

  const reloadSelected = () => {
    if (!selected) return;
    setDrafts((current) => ({ ...current, [selected.id]: selected.config }));
  };

  const saveSelected = async () => {
    if (!selected) return;
    setBusy(true);
    setError(null);
    try {
      const saved = await saveProfile(selected.engine, selected.name, draft);
      setProfiles((current) =>
        current.map((profile) => (profile.id === saved.id ? saved : profile)),
      );
      setDrafts((current) => ({ ...current, [saved.id]: saved.config }));
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
              key={profile.id}
              type="button"
              aria-label={`${profile.name} ${engineLabel(profile)}`}
              onClick={() => selectProfile(profile)}
              className={`rounded-md border p-3 text-left transition-colors ${
                selected?.id === profile.id
                  ? "border-primary bg-primary/5"
                  : "border-border bg-background hover:bg-accent"
              }`}
            >
              <span className="flex items-center gap-2">
                <span className="font-medium">{profile.name}</span>
                <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground">
                  {engineLabel(profile)}
                </span>
                {!sameConfig(
                  drafts[profile.id] ?? profile.config,
                  profile.config,
                ) && (
                  <span
                    className="ml-auto h-2 w-2 rounded-full bg-amber-500"
                    title="Unsaved changes"
                  />
                )}
              </span>
              <code className="mt-1 block text-[11px] text-muted-foreground">
                config/{profile.filename}
              </code>
            </button>
          ))}
          {!busy && profiles.length === 0 && (
            <p className="text-sm text-muted-foreground">
              No profile YAML files found.
            </p>
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
                    {engineLabel(selected)} profile
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  config/{selected.filename}
                </p>
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
              {(selected.name === "full" || draft.dast === true) &&
                selected.engine === "nuclei" && (
                  <div className="mb-5 rounded-md border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-800 dark:text-amber-200">
                    This profile can send intrusive exploit payloads. Production
                    and public scans still require explicit authorization.
                  </div>
                )}
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
                  <a
                    href={activeSection.sourceUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="ml-auto shrink-0 text-xs text-primary hover:underline"
                  >
                    Upstream flags ↗
                  </a>
                </div>
              </div>
              <div className="max-w-6xl rounded-lg border border-border bg-background p-5 shadow-sm">
                <JsonSchemaForm
                  key={`${selected.id}:${activeSection.id}`}
                  idPrefix={`${selected.engine}-${selected.name}-${activeSection.id}`}
                  schema={sectionSchema(activeSection)}
                  value={draft}
                  onChange={(next) =>
                    setDrafts((current) => ({
                      ...current,
                      [selected.id]: next,
                    }))
                  }
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
                Profile YAML is tracked in git. Keep credentials, bearer tokens,
                and private keys in external secret files rather than these
                fields.
              </p>
            </main>
          </div>
        )}
      </section>
    </div>
  );
}
