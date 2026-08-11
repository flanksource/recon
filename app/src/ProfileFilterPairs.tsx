// Collapses nuclei's paired include/exclude filter options into one control.
//
// The Filtering section declares `tags` and `exclude-tags` as two separate
// lists, and `type` and `exclude-type` as two more. That is how nuclei's flags
// are shaped, but it is not how the decision is made: you look at a tag once and
// decide whether it is in or out. Split across two fields, the same tag can be
// typed into both — nuclei then excludes it, and the profile reads as though it
// were included.
//
// A tri-state control makes the pair one question with three answers, and makes
// the contradictory state unreachable.

import { useCallback, useEffect, useState } from "react";
import { TriStateMultiSelect } from "@flanksource/clicky-ui";
import type {
  FieldControl,
  FilterBarMultiFilterMode,
  JsonSchemaProperty,
  PostExtension,
  PreExtension,
} from "@flanksource/clicky-ui";

import { fetchFilterOptions, fetchFilters } from "./api";

/** A nuclei include/exclude option pair, and where its vocabulary comes from. */
type Pair = {
  /** The key holding the included values, and the field the control replaces. */
  include: string;
  /** The key holding the excluded values, hidden from the form. */
  exclude: string;
  /**
   * The template filter whose vocabulary offers the values. Absent when the
   * schema already enumerates them, as `type` does.
   */
  vocabulary?: string;
  /** Whether a value the vocabulary does not list can still be committed. */
  custom: boolean;
  /** What the merged control does, replacing the included field's own wording. */
  description: string;
};

const PAIRS: Pair[] = [
  // Tags are open: nuclei matches whatever a template declares, and a templates
  // release can add one the installed catalogue has never seen.
  {
    include: "tags",
    exclude: "exclude-tags",
    vocabulary: "tag",
    custom: true,
    description:
      "Template tags to include or exclude. Excluding wins; leave a tag unset to ignore it.",
  },
  // Protocols are closed — the schema enumerates every one nuclei speaks.
  {
    include: "type",
    exclude: "exclude-type",
    custom: false,
    description:
      "Template protocols to include or exclude. Nothing included means every protocol.",
  },
];

/** The keys the paired controls take over, so the form stops rendering them. */
export const PAIRED_KEYS = PAIRS.map((pair) => pair.exclude);

/**
 * Builds the form extensions that render the paired controls.
 *
 * `post` replaces the included field's control; `hiddenKeys` removes the
 * excluded field. The schema stays the engine's own — this changes how two of
 * its options are edited, not what the engine accepts.
 */
export function useProfileFilterPairs(): {
  pre: PreExtension[];
  post: PostExtension[];
  hiddenKeys: string[];
} {
  const [vocabularies, setVocabularies] = useState<Record<string, string[]>>({});

  useEffect(() => {
    let live = true;
    fetchFilters("template")
      .then((loaded) => {
        if (!live) return;
        setVocabularies(
          Object.fromEntries(loaded.map((filter) => [filter.key, filter.options])),
        );
      })
      // A missing catalogue costs the suggestions, not the control: the values
      // are still typeable, and a profile is editable on a machine whose
      // templates are not installed.
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);

  const search = useCallback(
    (key: string, query: string) =>
      fetchFilterOptions("template", key, query)
        .then((options) => options.map((value) => ({ value, label: value })))
        .catch(() => []),
    [],
  );

  const post = useCallback<PostExtension>(
    (field, nodes, ctx) => {
      const pair = PAIRS.find((candidate) => candidate.include === field.key);
      if (!pair || !ctx?.onRootChange) return nodes;

      const config = ctx.rootValue ?? {};
      const options = (
        pair.vocabulary ? (vocabularies[pair.vocabulary] ?? []) : enumOf(field.schema)
      ).map((value) => ({ value, label: value }));

      return {
        label: nodes.label,
        value: (
          <TriStateMultiSelect
            label={field.label}
            value={modesOf(config[pair.include], config[pair.exclude])}
            options={options}
            allowCustomValue={pair.custom}
            {...(pair.vocabulary
              ? { onSearch: (query: string) => search(pair.vocabulary as string, query) }
              : {})}
            onChange={(modes) => ctx.onRootChange?.(applyPair(config, pair, modes))}
          />
        ),
      };
    },
    [search, vocabularies],
  );

  // The included field's own description says "tags to include", which stops
  // being true once the control does both halves.
  const pre = useCallback<PreExtension>((field) => {
    const pair = PAIRS.find((candidate) => candidate.include === field.key);
    return pair ? { ...field, description: pair.description } : field;
  }, []);

  return { pre: [pre], post: [post], hiddenKeys: PAIRED_KEYS };
}

/** enumOf reads the values an array-of-enum property allows. */
function enumOf(schema: JsonSchemaProperty | undefined): string[] {
  const items = schema?.items as { enum?: unknown[] } | undefined;
  return (items?.enum ?? []).map(String);
}

function listOf(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

/**
 * Reads the two lists as one set of modes.
 *
 * Exclusion wins when a value somehow appears in both, because that is what
 * nuclei does with it. Showing it as included would describe a scan that does
 * not happen.
 */
function modesOf(
  include: unknown,
  exclude: unknown,
): Record<string, FilterBarMultiFilterMode> {
  const modes: Record<string, FilterBarMultiFilterMode> = {};
  for (const value of listOf(include)) modes[value] = "include";
  for (const value of listOf(exclude)) modes[value] = "exclude";
  return modes;
}

/**
 * Writes the modes back to the pair of keys.
 *
 * An emptied list is removed rather than stored as `[]`: a profile is compared
 * to its saved copy by value, so an empty key left behind reads as an unsaved
 * change forever and is sent to the engine as an option nobody set.
 */
function applyPair(
  config: Record<string, unknown>,
  pair: Pair,
  modes: Record<string, FilterBarMultiFilterMode>,
): Record<string, unknown> {
  const include: string[] = [];
  const exclude: string[] = [];
  for (const [value, mode] of Object.entries(modes)) {
    (mode === "exclude" ? exclude : include).push(value);
  }

  const next = { ...config };
  assign(next, pair.include, include);
  assign(next, pair.exclude, exclude);
  return next;
}

function assign(config: Record<string, unknown>, key: string, values: string[]) {
  if (values.length === 0) delete config[key];
  else config[key] = values;
}

// Exported for the specs, which assert the mapping rather than the rendering.
export const __test = { modesOf, applyPair, enumOf, PAIRS };

export type { FieldControl };
