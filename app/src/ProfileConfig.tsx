import { useEffect, useMemo, useState } from "react";
import {
  Button,
  JsonSchemaForm,
  type JsonSchemaObject,
} from "@flanksource/clicky-ui";
import { useProfileFilterPairs } from "./ProfileFilterPairs";
import { profileId } from "./types";
import type { Engine, EngineSection, Profile } from "./types";

// SchemaProperty (the server's wire type) and JsonSchemaProperty (the form's
// type) are the same JSON Schema fragment; only `type`'s literal-vs-string
// typing differs, so the cast is a nominal bridge, not a data transform.
export function sectionSchema(section: EngineSection): JsonSchemaObject {
  return {
    type: "object",
    properties: section.properties,
  } as unknown as JsonSchemaObject;
}

export function sameConfig(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

type Props = {
  engine: Engine;
  profile: Profile;
  value: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
  onReset: () => void;
  /** What editing here does, in the caller's own words. */
  note?: string;
};

export function ProfileConfig({
  engine,
  profile,
  value,
  onChange,
  onReset,
  note,
}: Props) {
  const sections = engine.sections;
  const { pre, post, hiddenKeys } = useProfileFilterPairs();
  const [sectionId, setSectionId] = useState(sections[0]?.id ?? "");
  const activeSection =
    sections.find((section) => section.id === sectionId) ?? sections[0];
  const tweaked = useMemo(
    () => !sameConfig(value, profile.config),
    [profile.config, value],
  );

  useEffect(
    () => setSectionId(sections[0]?.id ?? ""),
    [profileId(profile), sections],
  );
  if (!activeSection)
    throw new Error(`${engine.title} profile schema has no sections`);

  return (
    <div className="flex min-h-0 flex-1 overflow-hidden rounded-md border border-border">
      <nav className="w-48 shrink-0 space-y-1 overflow-y-auto border-r border-border bg-muted/20 p-2">
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
      <section className="min-w-0 flex-1 overflow-y-auto p-4">
        <div className="mb-4 flex items-start gap-3">
          <div>
            <h3 className="font-semibold">{activeSection.title}</h3>
            <p className="mt-1 text-sm text-muted-foreground">
              {activeSection.description}
            </p>
          </div>
          <span className="flex-1" />
          {tweaked ? (
            <span className="pt-2 text-xs text-amber-600 dark:text-amber-400">
              Unsaved changes
            </span>
          ) : null}
          <Button
            variant="outline"
            size="sm"
            disabled={!tweaked}
            onClick={onReset}
          >
            Reset changes
          </Button>
        </div>
        <JsonSchemaForm
          key={`${profileId(profile)}:${activeSection.id}`}
          idPrefix={`${profile.engine}-${profile.name}-${activeSection.id}`}
          schema={sectionSchema(activeSection)}
          value={value}
          onChange={onChange}
          pre={pre}
          post={post}
          hiddenKeys={hiddenKeys}
          layout={{ mode: "stacked", help: "hover", valueMaxWidth: "100%" }}
          size="sm"
          preferencesStorageKey="run-profile-form-preferences"
        />
        <p className="mt-4 text-xs text-muted-foreground">
          {note ??
            `Changes here update the "${profile.name}" profile before this run.`}
        </p>
      </section>
    </div>
  );
}
