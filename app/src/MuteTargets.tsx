// The inventory scope of a mute rule.
//
// Two controls over one value, deliberately. The filter bar is the same one the
// inventory listing uses, so scoping a rule reads like filtering targets and the
// vocabulary comes from the database rather than from a list kept in step by
// hand. The JSON box below it is the escape hatch for the fields the bar does
// not offer — a label selector, a last-seen window — and for reading back what
// a rule imported from elsewhere actually says.

import { useCallback, useEffect, useMemo, useState } from "react";
import { FilterBar } from "@flanksource/clicky-ui/components";
import { useEntityFilters } from "./filters";
import type { FilterSelection } from "./types";

type Props = {
  targets: Record<string, unknown> | undefined;
  onChange: (targets: Record<string, unknown> | undefined) => void;
};

/**
 * The filter control keys whose selector field is named differently.
 *
 * The bar is generated from the CLI flags — `--id` — while a stored selector is
 * the JSON shape — `ids`. They are the same field and the difference is not
 * cosmetic: an unknown key decodes to an empty selector, which resolves to
 * every target rather than to none.
 */
const SELECTOR_KEY: Record<string, string> = { id: "ids" };

/** Selector fields the server reads as numbers rather than strings. */
const NUMERIC = new Set(["ports", "status"]);

/** Selector fields the filter bar does not offer, kept when it round-trips. */
const BAR_KEYS = new Set([
  "id",
  "kind",
  "provider",
  "class",
  "tags",
  "profiles",
  "hosts",
  "ports",
  "status",
  "failure",
]);

function toSelector(selection: FilterSelection): Record<string, unknown> {
  const selector: Record<string, unknown> = {};
  for (const [key, values] of Object.entries(selection)) {
    if (values.length === 0) continue;
    const field = SELECTOR_KEY[key] ?? key;
    selector[field] = NUMERIC.has(field)
      ? values.map((value) => Number(value)).filter((value) => Number.isFinite(value))
      : values;
  }
  return selector;
}

function toSelection(targets: Record<string, unknown> | undefined): FilterSelection {
  if (!targets) return {};
  const selection: FilterSelection = {};
  for (const barKey of BAR_KEYS) {
    const field = SELECTOR_KEY[barKey] ?? barKey;
    const value = targets[field];
    if (Array.isArray(value) && value.length > 0) {
      selection[barKey] = value.map((entry) => String(entry));
    }
  }
  return selection;
}

/** Fields the bar cannot show, so an edit through it does not discard them. */
function beyondTheBar(targets: Record<string, unknown> | undefined): Record<string, unknown> {
  if (!targets) return {};
  const fields = new Set([...BAR_KEYS].map((key) => SELECTOR_KEY[key] ?? key));
  return Object.fromEntries(
    Object.entries(targets).filter(([key]) => !fields.has(key)),
  );
}

export function MuteTargets({ targets, onChange }: Props) {
  const { filters, selection, setSelection, error } = useEntityFilters("target");
  const [advanced, setAdvanced] = useState(false);
  const [draft, setDraft] = useState(() => JSON.stringify(targets ?? {}, null, 2));
  const [invalid, setInvalid] = useState<string | null>(null);

  const scoped = useMemo(() => Object.keys(targets ?? {}).length > 0, [targets]);

  // Seed the bar from the rule. Keyed on the serialised selector so switching
  // rules re-seeds, while an edit made through the bar does not bounce back.
  const serialised = JSON.stringify(targets ?? {});
  useEffect(() => {
    setSelection(toSelection(targets));
    setDraft(JSON.stringify(targets ?? {}, null, 2));
    setInvalid(null);
    // setSelection is stable for the hook's lifetime; re-running on it would
    // fight every keystroke.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serialised]);

  // Push what the bar holds back onto the rule, preserving the fields the bar
  // cannot show rather than dropping them on the first click.
  const barSerialised = JSON.stringify(selection);
  useEffect(() => {
    const next = { ...beyondTheBar(targets), ...toSelector(selection) };
    if (JSON.stringify(next) === serialised) return;
    onChange(Object.keys(next).length > 0 ? next : undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [barSerialised]);

  const applyAdvanced = useCallback(
    (text: string) => {
      setDraft(text);
      if (text.trim() === "") {
        setInvalid(null);
        onChange(undefined);
        return;
      }
      try {
        const parsed: unknown = JSON.parse(text);
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
          setInvalid("A target selector is a JSON object, e.g. {\"class\":[\"non-prod\"]}");
          return;
        }
        setInvalid(null);
        const next = parsed as Record<string, unknown>;
        onChange(Object.keys(next).length > 0 ? next : undefined);
      } catch (cause) {
        setInvalid((cause as Error).message);
      }
    },
    [onChange],
  );

  return (
    <div>
      <div className="mb-1 flex items-center gap-2">
        <span className="text-xs font-medium">Targets</span>
        <span className="flex-1" />
        <button
          type="button"
          className="text-xs text-primary underline"
          onClick={() => setAdvanced((on) => !on)}
        >
          {advanced ? "Hide JSON" : "Advanced"}
        </button>
      </div>

      <p className="mb-2 text-xs text-muted-foreground">
        {scoped
          ? "Only findings from the targets this selector matches."
          : "Every target. Narrow it to keep a rule from reaching further than intended."}
      </p>

      {error && (
        <p role="alert" className="mb-2 text-xs text-destructive">
          Target filters unavailable: {error}
        </p>
      )}

      <FilterBar filters={filters} className="rounded border border-border p-2" />

      {advanced && (
        <div className="mt-2">
          <textarea
            aria-label="Targets JSON"
            className="h-24 w-full rounded border border-border bg-background px-2 py-1 font-mono text-xs"
            value={draft}
            onChange={(event) => applyAdvanced(event.target.value)}
          />
          <p className="mt-1 text-xs text-muted-foreground">
            The stored selector. Accepts every field the inventory does, including ones the bar
            has no control for — <code>selector</code> for a label expression,{" "}
            <code>lastSeen</code>, <code>live</code>.
          </p>
          {invalid && (
            <p role="alert" className="mt-1 text-xs text-destructive">
              {invalid}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
