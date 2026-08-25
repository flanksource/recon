// Renders an engine's mutually-exclusive option groups as one segmented control.
//
// Prowler declares `checks | services | compliance | categories |
// resource-groups` as a single argparse choice, but the schema lists them as
// five independent multi-selects. Setting two is the obvious thing to do, and
// the profile saves — the scan then fails at command-build time with the name
// of a generated group nobody can look up.
//
// A segmented control makes the group one question. The invalid combination is
// unreachable, and which of the five is in play is legible at a glance rather
// than being whichever field happens to be non-empty.

import { useCallback, useEffect, useState } from "react";
import { SegmentedControl } from "@flanksource/clicky-ui/components";
import type {
  JsonSchemaObject,
  JsonSchemaProperty,
  PostExtension,
  PreExtension,
} from "@flanksource/clicky-ui/components";

/** One option in a group, and how selecting it is expressed in the config. */
export type MutexMember = {
  key: string;
  label: string;
};

export type MutexGroup = {
  id: string;
  title: string;
  /**
   * The label the row carries, empty when the section heading already asks the
   * question. argparse names a group after the section it was declared in, so
   * for a section holding one group the two read identically.
   */
  label: string;
  members: MutexMember[];
  /**
   * `store_true` members carry no value of their own, so the segment is the
   * whole answer: selecting one writes `true` and nothing else is rendered.
   */
  flag: boolean;
  /** Auth-mode groups read as "which credential", not "how much to scan". */
  credentialSelector: boolean;
};

/** The segment standing for "no member selected", which every group allows. */
const NONE = "__none";

/**
 * Reads the groups a section owns.
 *
 * Groups live on the schema root while the form renders one projected section
 * at a time, so a group is claimed by the section holding all of its keys. One
 * spanning two sections would render a control governing fields the reader
 * cannot see, so it fails rather than rendering half a question.
 */
export function sectionMutexGroups(options: {
  root: JsonSchemaObject;
  sectionTitle: string;
  sectionKeys: string[];
  describe: (message: string) => string;
}): MutexGroup[] {
  const { root, sectionTitle, sectionKeys, describe } = options;
  const declared = root["x-mutual-exclusions"];
  if (declared === undefined) return [];
  if (!Array.isArray(declared)) {
    throw new Error(describe("x-mutual-exclusions must be an array"));
  }
  const properties = root.properties ?? {};
  const groups: MutexGroup[] = [];
  for (const item of declared) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new Error(describe("x-mutual-exclusions has an invalid group"));
    }
    const group = item as Record<string, unknown>;
    if (typeof group.id !== "string" || !Array.isArray(group.keys)) {
      throw new Error(describe("mutual exclusion requires id and keys"));
    }
    const keys = group.keys.map(String);
    const inSection = keys.filter((key) => sectionKeys.includes(key));
    if (inSection.length === 0) continue;
    if (inSection.length !== keys.length) {
      throw new Error(
        describe(`mutual exclusion "${group.id}" spans more than one section`),
      );
    }
    for (const key of keys) {
      if (!properties[key]) {
        throw new Error(
          describe(`mutual exclusion "${group.id}" references unknown property "${key}"`),
        );
      }
    }
    const title = typeof group.title === "string" && group.title ? group.title : group.id;
    groups.push({
      id: group.id,
      title,
      label: title === sectionTitle ? "" : title,
      members: keys.map((key) => ({ key, label: labelOf(key, properties[key]) })),
      flag: keys.every((key) => properties[key]?.type === "boolean"),
      credentialSelector: keys.every(
        (key) => properties[key]?.["x-credential-selector"] === true,
      ),
    });
  }
  return groups;
}

/**
 * Builds the form extensions that render each group as one control.
 *
 * `pre` drops every member but the host; `post` replaces the host's control
 * with the segments, and lets the selected member's own control follow. The
 * schema stays the engine's own — this changes how a group is edited, not what
 * the engine accepts.
 */
export function useMutualExclusions(
  groups: MutexGroup[],
  identity: string,
): { pre: PreExtension[]; post: PostExtension[] } {
  // A chosen member holds no value until the reader supplies one, so the
  // selection cannot be read back out of the config alone.
  const [choice, setChoice] = useState<Record<string, string>>({});
  useEffect(() => setChoice({}), [identity]);

  const stateOf = useCallback(
    (group: MutexGroup, config: Record<string, unknown>) => {
      const active = group.members
        .map((member) => member.key)
        .filter((key) => valueIsActive(config[key]));
      const selected =
        active.length === 1 ? active[0] : active.length > 1 ? NONE : (choice[group.id] ?? NONE);
      const host = selected === NONE || group.flag ? group.members[0].key : selected;
      return { active, selected, host, conflicted: active.length > 1 };
    },
    [choice],
  );

  const groupOf = useCallback(
    (key: string) => groups.find((group) => group.members.some((member) => member.key === key)),
    [groups],
  );

  const pre = useCallback<PreExtension>(
    (field, ctx) => {
      const group = groupOf(field.key);
      if (!group) return field;
      const state = stateOf(group, ctx.rootValue ?? {});
      // Hiding a member of a conflicting pair would hide the value that breaks
      // the scan, leaving nothing to correct in the form.
      if (state.conflicted) return field;
      if (field.key !== state.host) return null;
      // The row asks the group's question, not the host member's, so the label
      // is set here rather than in `post`: FieldLabel renders it with the same
      // typography, `for` binding and help affordance as every other field.
      const showsMember = !group.flag && state.selected !== NONE;
      return {
        ...field,
        label: group.label,
        ...(showsMember ? {} : { description: undefined }),
      };
    },
    [groupOf, stateOf],
  );

  const post = useCallback<PostExtension>(
    (field, nodes, ctx) => {
      const group = groupOf(field.key);
      if (!group || !ctx?.onRootChange) return nodes;
      const config = ctx.rootValue ?? {};
      const state = stateOf(group, config);

      if (state.conflicted) {
        if (field.key !== state.active[0]) return nodes;
        return {
          label: nodes.label,
          value: (
            <div className="space-y-2">
              <p role="alert" className="text-xs text-destructive">
                {group.title} accepts only one of {state.active.join(", ")}. Clear all but one.
              </p>
              {nodes.value}
            </div>
          ),
        };
      }
      if (field.key !== state.host) return nodes;

      return {
        label: nodes.label,
        value: (
          <div className="space-y-2">
            <SegmentedControl
              size="sm"
              wrap
              aria-label={group.title}
              value={state.selected}
              options={[
                { id: NONE, label: group.credentialSelector ? "Credentials" : "Everything" },
                ...group.members.map((member) => ({ id: member.key, label: member.label })),
              ]}
              onChange={(id) => {
                setChoice((previous) => ({ ...previous, [group.id]: id }));
                ctx.onRootChange?.(applySelection(config, group, id));
              }}
            />
            {!group.flag && state.selected !== NONE ? nodes.value : null}
          </div>
        ),
      };
    },
    [groupOf, stateOf],
  );

  return groups.length > 0 ? { pre: [pre], post: [post] } : { pre: [], post: [] };
}

/**
 * Writes the selection back over the whole group.
 *
 * Members are deleted rather than emptied: a profile is compared to its saved
 * copy by value, so an empty key left behind reads as an unsaved change forever
 * and is sent to the engine as an option nobody set. A `store_true` member is
 * the exception — there the segment is the value.
 */
export function applySelection(
  config: Record<string, unknown>,
  group: MutexGroup,
  selected: string,
): Record<string, unknown> {
  const next = { ...config };
  for (const member of group.members) delete next[member.key];
  if (selected !== NONE && group.flag) next[selected] = true;
  return next;
}

/** Mirrors valueIsActive in the engine, which decides the same question. */
export function valueIsActive(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.length > 0;
  return true;
}

function labelOf(key: string, property: JsonSchemaProperty | undefined): string {
  return typeof property?.title === "string" && property.title ? property.title : key;
}
