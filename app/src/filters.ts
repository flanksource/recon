// Filter controls built from what the server says a listing offers.
//
// Every entity declares its filters in Go, so the option sets here are the same
// ones `reconctl target list --class <tab>` completes against. Nothing in this
// file knows that a class is one of five words or that a tag is free text — ask
// the listing and it says, which is what stops the browser's idea of the
// vocabulary from drifting away from the database's.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { FilterBarFilter, FilterBarMultiFilterMode } from "@flanksource/clicky-ui/components";

import { fetchFilterOptions, fetchFilters } from "./api";
import type { FilterSelection, FilterVocabulary } from "./types";

/**
 * Filters whose server-side predicate honours a leading `!` as "exclude".
 *
 * These are the vocabularies where "everything except" is the question worth
 * asking: a template is tagged half a dozen ways and speaks one protocol, so
 * narrowing by subtraction is often shorter than listing what you want. A
 * severity or a class is neither — you pick from six, you do not carve them up.
 *
 * The list is short because it has to stay true. Rendering a tri-state control
 * over a filter the server reads as a literal value would send `!dos` as a tag
 * name, match nothing, and look like a working exclusion. The Go side honours
 * `!` for exactly these keys: TemplateOpts.Tag and .Type via
 * collections.MatchItems, FindingOpts.Tag and TargetOpts.Tags via tagPredicate.
 */
const NEGATABLE = new Set(["label", "tag", "tags", "type"]);

/**
 * Loads a listing's filter controls and holds the current selection.
 *
 * Most controls are include-only, matching the server: a selector means "any of
 * these". The vocabularies in NEGATABLE get a tri-state control instead, where
 * each value can be included or excluded — the two the Go side reads as
 * patterns rather than as literal values.
 */
export function useEntityFilters(
  entity: string,
  // Filters another control already owns. A findings list scoped to one run
  // must not also offer to pick the run: two controls over one value disagree
  // the moment either is used.
  options: { exclude?: string[] } = {},
): {
  filters: FilterBarFilter[];
  selection: FilterSelection;
  setSelection: (selection: FilterSelection) => void;
  error: string | null;
} {
  const excluded = options.exclude?.join(",") ?? "";
  const [vocabularies, setVocabularies] = useState<FilterVocabulary[]>([]);
  const [selection, setSelection] = useState<FilterSelection>({});
  const [searched, setSearched] = useState<Record<string, string[]>>({});
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const hidden = new Set(excluded ? excluded.split(",") : []);
    fetchFilters(entity)
      .then((loaded) => live && setVocabularies(loaded.filter((f) => !hidden.has(f.key))))
      .catch((e: Error) => live && setError(e.message));
    return () => {
      live = false;
    };
  }, [entity, excluded]);

  // Returns the matches as well as recording them. The two control kinds read
  // the result differently: `lookup-multi` re-reads its `options` prop, while
  // the tri-state `multi` merges whatever the promise resolves to and shows "No
  // results" if it resolves to nothing — so a search that only set state left
  // every value past the head set unreachable.
  const search = useCallback(
    (key: string, query: string): Promise<{ value: string; label: string }[]> =>
      fetchFilterOptions(entity, key, query)
        .then((options) => {
          setSearched((current) => ({ ...current, [key]: options }));
          return options.map((value) => ({ value, label: value }));
        })
        .catch((e: Error) => {
          setError(e.message);
          return [];
        }),
    [entity],
  );

  const filters = useMemo<FilterBarFilter[]>(
    () =>
      vocabularies.map((vocabulary) => {
        // A search replaces the head set for that control, which is what the
        // server-side narrowing is for; until one runs, the head is all there is.
        const options = (searched[vocabulary.key] ?? vocabulary.options).map((value) => ({
          value,
          label: value,
        }));
        const values = selection[vocabulary.key] ?? [];
        const shared = {
          key: vocabulary.key,
          label: vocabulary.label,
          options,
          truncated: vocabulary.truncated,
          total: vocabulary.total,
        };

        if (NEGATABLE.has(vocabulary.key)) {
          return {
            ...shared,
            kind: "multi",
            value: modesOf(values),
            onChange: (modes: Record<string, FilterBarMultiFilterMode>) =>
              setSelection((current) => withValues(current, vocabulary.key, patternsOf(modes))),
            onSearch: (query: string) => search(vocabulary.key, query),
          };
        }

        return {
          ...shared,
          kind: "lookup-multi",
          value: values,
          onChange: (next: string[]) =>
            setSelection((current) => withValues(current, vocabulary.key, next)),
          onSearch: (query: string) => {
            void search(vocabulary.key, query);
          },
        };
      }),
    [search, searched, selection, vocabularies],
  );

  return { filters, selection, setSelection, error };
}

// The selection is stored as the patterns the server takes — `dos` and `!dos` —
// rather than as the control's mode map. Keeping one representation means
// selectionQuery stays a join, a selection can be read straight out of a URL,
// and the include-only controls need no special case.

function modesOf(patterns: string[]): Record<string, FilterBarMultiFilterMode> {
  const modes: Record<string, FilterBarMultiFilterMode> = {};
  for (const pattern of patterns) {
    if (pattern.startsWith("!")) modes[pattern.slice(1)] = "exclude";
    else modes[pattern] = "include";
  }
  return modes;
}

function patternsOf(modes: Record<string, FilterBarMultiFilterMode>): string[] {
  return Object.entries(modes).map(([value, mode]) =>
    mode === "exclude" ? `!${value}` : value,
  );
}

// withValues drops a filter entirely when nothing is selected, so an empty
// control does not become an empty query parameter the server has to interpret.
function withValues(
  selection: FilterSelection,
  key: string,
  values: string[],
): FilterSelection {
  const next = { ...selection };
  if (values.length === 0) delete next[key];
  else next[key] = values;
  return next;
}

/**
 * Renders a selection as the query string a listing takes.
 *
 * Values are comma-joined because a selector field is a repeated flag on the
 * CLI, and that is how repeated flags arrive over HTTP.
 */
export function selectionQuery(selection: FilterSelection): Record<string, string> {
  return Object.fromEntries(
    Object.entries(selection).map(([key, values]) => [key, values.join(",")]),
  );
}

/** Renders a selection as the phrase shown when it is worth naming. */
export function selectionLabel(selection: FilterSelection): string {
  const parts = Object.entries(selection)
    .filter(([, values]) => values.length > 0)
    .map(([key, values]) => `${key} ${values.join(",")}`);
  return parts.length ? parts.join(", ") : "every target";
}
