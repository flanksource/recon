// Filter controls built from what the server says a listing offers.
//
// Every entity declares its filters in Go, so the option sets here are the same
// ones `reconctl target list --class <tab>` completes against. Nothing in this
// file knows that a class is one of five words or that a tag is free text — ask
// the listing and it says, which is what stops the browser's idea of the
// vocabulary from drifting away from the database's.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { FilterBarFilter } from "@flanksource/clicky-ui";

import { fetchFilterOptions, fetchFilters } from "./api";
import type { FilterSelection, FilterVocabulary } from "./types";

/**
 * Loads a listing's filter controls and holds the current selection.
 *
 * The controls are include-only, matching the server: a selector means "any of
 * these", and there is no way to express an exclusion that the Go side would
 * honour. Offering one would send `!prod` as a class and be refused.
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

  const search = useCallback(
    (key: string, query: string) => {
      fetchFilterOptions(entity, key, query)
        .then((options) => setSearched((current) => ({ ...current, [key]: options })))
        .catch((e: Error) => setError(e.message));
    },
    [entity],
  );

  const filters = useMemo<FilterBarFilter[]>(
    () =>
      vocabularies.map((vocabulary) => ({
        key: vocabulary.key,
        kind: "lookup-multi",
        label: vocabulary.label,
        value: selection[vocabulary.key] ?? [],
        // A search replaces the head set for that control, which is what the
        // server-side narrowing is for; until one runs, the head is all there is.
        options: (searched[vocabulary.key] ?? vocabulary.options).map((value) => ({ value })),
        onChange: (values: string[]) =>
          setSelection((current) => withValues(current, vocabulary.key, values)),
        onSearch: (query: string) => search(vocabulary.key, query),
        truncated: vocabulary.truncated,
        total: vocabulary.total,
      })),
    [search, searched, selection, vocabularies],
  );

  return { filters, selection, setSelection, error };
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
