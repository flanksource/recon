import { useEffect, useMemo, useState } from "react";
import { Button, JsonSchemaForm } from "@flanksource/clicky-ui";
import { profileSections, sectionSchema } from "../profile-schema/index.ts";
import type { ProfileDocument } from "./types";

type Props = {
  profile: ProfileDocument;
  value: Record<string, unknown>;
  onChange: (value: Record<string, unknown>) => void;
  onReset: () => void;
};

export function ScanProfileConfig({
  profile,
  value,
  onChange,
  onReset,
}: Props) {
  const sections = profileSections.nuclei;
  const [sectionId, setSectionId] = useState(sections[0]?.id ?? "");
  const activeSection =
    sections.find((section) => section.id === sectionId) ?? sections[0];
  const tweaked = useMemo(
    () => JSON.stringify(value) !== JSON.stringify(profile.config),
    [profile.config, value],
  );

  useEffect(() => setSectionId(sections[0]?.id ?? ""), [profile.id, sections]);
  if (!activeSection) throw new Error("Nuclei profile schema has no sections");

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
              Tweaked for this run
            </span>
          ) : null}
          <Button variant="outline" size="sm" disabled={!tweaked} onClick={onReset}>
            Reset tweaks
          </Button>
        </div>
        <JsonSchemaForm
          key={`${profile.id}:${activeSection.id}`}
          idPrefix={`scan-${profile.name}-${activeSection.id}`}
          schema={sectionSchema(activeSection)}
          value={value}
          onChange={onChange}
          layout={{ mode: "stacked", help: "hover", valueMaxWidth: "100%" }}
          size="sm"
          preferencesStorageKey="nuclei-run-profile-form-preferences"
        />
        <p className="mt-4 text-xs text-muted-foreground">
          Changes apply only to this scan. The tracked profile is not modified.
        </p>
      </section>
    </div>
  );
}
