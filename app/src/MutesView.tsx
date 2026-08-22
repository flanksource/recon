import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { MuteForm } from "./MuteForm";
import { NEW_MUTE, mutePrefillDraft, suggestMuteName } from "./mute-prefill";
import {
  createMute,
  deleteMute,
  fetchMutes,
  previewMute,
  updateMute,
} from "./api-mutes";
import { fetchEngines } from "./api";
import type { MutePreview, MuteRule } from "./mute-types";

type Props = {
  /**
   * The rule the route addresses, or `NEW_MUTE` for one that does not exist
   * yet. Which rule is open lives in the URL rather than in state here, so a
   * rule can be linked to — including from a finding, which is where the
   * decision to mute is actually made.
   */
  selected?: string;
  onSelect: (name?: string) => void;
  /**
   * The query a new rule is prefilled from. Injected rather than read from
   * `window` so the prefill can be tested without a router.
   */
  search?: string;
};

export function MutesView({ selected, onSelect, search }: Props) {
  const [rules, setRules] = useState<MuteRule[]>([]);
  const [engines, setEngines] = useState<string[]>([]);
  const [draft, setDraft] = useState<MuteRule | null>(null);
  const [preview, setPreview] = useState<MutePreview | null>(null);
  const [previewing, setPreviewing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isNew = selected === NEW_MUTE;

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const [stored, scanners] = await Promise.all([
        fetchMutes(),
        fetchEngines("scan"),
      ]);
      setRules(stored);
      setEngines(scanners.map((engine) => engine.name));
      setLoaded(true);
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // The route drives which rule is being edited. Seeding a new draft is kept
  // off the rules list deliberately: the list changes when a save reloads it,
  // and reseeding then would discard whatever was being typed.
  const query = search ?? "";
  useEffect(() => {
    if (!isNew) return;
    setPreview(null);
    setDraft(mutePrefillDraft(query));
  }, [isNew, query]);

  // An existing rule does re-run on the list, because a deep link lands here
  // before the rule it names has loaded.
  useEffect(() => {
    if (isNew) return;
    setPreview(null);
    if (selected === undefined) {
      setDraft(null);
      return;
    }
    const rule = rules.find((candidate) => candidate.name === selected);
    if (rule) setDraft({ ...rule });
  }, [selected, isNew, rules]);

  // Named once the stored names are known, so the suggestion cannot collide
  // with an existing rule — the server upserts on the name, so a collision
  // would rewrite that rule rather than add one. Only ever fills a blank, so
  // it never overwrites a name someone typed.
  useEffect(() => {
    if (!isNew || !loaded) return;
    setDraft((current) =>
      current && current.name === ""
        ? { ...current, name: suggestMuteName(current, rules.map((rule) => rule.name)) }
        : current,
    );
  }, [isNew, loaded, rules]);

  const save = useCallback(async () => {
    if (!draft) return;
    setBusy(true);
    setError(null);
    try {
      const saved = isNew ? await createMute(draft) : await updateMute(draft.name, draft);
      await load();
      // A created rule stops being `new`: address it by the name it now has, so
      // a reload reopens the rule rather than a fresh draft.
      onSelect(saved.name);
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }, [draft, isNew, load, onSelect]);

  const remove = useCallback(async () => {
    if (!draft || isNew) return;
    setBusy(true);
    setError(null);
    try {
      await deleteMute(draft.name);
      onSelect(undefined);
      await load();
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setBusy(false);
    }
  }, [draft, isNew, load, onSelect]);

  const check = useCallback(async () => {
    if (!draft || isNew) return;
    setPreviewing(true);
    setError(null);
    try {
      setPreview(await previewMute(draft.name));
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setPreviewing(false);
    }
  }, [draft, isNew]);

  const active = useMemo(() => rules.filter((rule) => !rule.disabled).length, [rules]);
  const missing =
    selected !== undefined && !isNew && loaded && !rules.some((rule) => rule.name === selected);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <div>
          <h1 className="text-lg font-semibold">Mutes</h1>
          <p className="text-xs text-muted-foreground">
            Findings that have been accepted. A muted finding is not recorded — each run's
            mutes.json says which rule removed what.
          </p>
        </div>
        <span className="flex-1" />
        <span className="text-xs text-muted-foreground">
          {rules.length} rule{rules.length === 1 ? "" : "s"}
          {rules.length !== active && `, ${rules.length - active} disabled`}
        </span>
        <Button size="sm" onClick={() => onSelect(NEW_MUTE)}>
          New rule
        </Button>
      </header>

      {error && (
        <div role="alert" className="border-b border-border px-4 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="flex min-h-0 flex-1">
        <nav className="w-64 shrink-0 overflow-y-auto border-r border-border">
          {busy && rules.length === 0 && (
            <p className="p-3 text-sm text-muted-foreground">Loading rules…</p>
          )}
          {loaded && rules.length === 0 && (
            <p className="p-3 text-sm text-muted-foreground">
              No mute rules. Everything an engine reports is recorded.
            </p>
          )}
          <ul>
            {rules.map((rule) => (
              <li key={rule.name}>
                <button
                  type="button"
                  aria-current={selected === rule.name}
                  onClick={() => onSelect(rule.name)}
                  className={`flex w-full flex-col gap-0.5 border-b border-border px-3 py-2 text-left text-sm ${
                    selected === rule.name ? "bg-muted" : ""
                  }`}
                >
                  <span className="flex items-center gap-2">
                    <span className="truncate font-medium">{rule.name}</span>
                    {rule.disabled && (
                      <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase text-muted-foreground">
                        off
                      </span>
                    )}
                  </span>
                  <span className="truncate text-xs text-muted-foreground">
                    {summarise(rule)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <main className="flex min-h-0 flex-1 flex-col">
          {missing ? (
            <div className="p-4 text-sm text-muted-foreground">
              <p role="alert">
                No mute rule named <code>{selected}</code>. It may have been deleted.
              </p>
              <button
                className="mt-2 text-sm text-primary underline"
                onClick={() => onSelect(undefined)}
              >
                Back to the rules
              </button>
            </div>
          ) : draft ? (
            <MuteForm
              rule={draft}
              engines={engines}
              isNew={isNew}
              busy={busy}
              preview={preview}
              previewing={previewing}
              onChange={setDraft}
              onSave={() => void save()}
              onDelete={() => void remove()}
              onPreview={() => void check()}
            />
          ) : (
            <p className="p-4 text-sm text-muted-foreground">
              Select a rule, or create one to accept a finding you do not intend to act on.
            </p>
          )}
        </main>
      </div>
    </div>
  );
}

/** One line saying what a rule covers, for the list. */
function summarise(rule: MuteRule): string {
  const parts: string[] = [];
  if (rule.templates?.length) parts.push(rule.templates.join(", "));
  if (rule.resources?.length) parts.push(`on ${rule.resources.join(", ")}`);
  if (rule.tags?.length) parts.push(`tagged ${rule.tags.join(", ")}`);
  if (rule.severity?.length) parts.push(rule.severity.join("/"));
  if (rule.expr) parts.push("expression");
  return parts.join(" · ") || "everything";
}
