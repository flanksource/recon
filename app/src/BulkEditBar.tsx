import { useState } from "react";
import { Button, MultiSelect, Select } from "@flanksource/clicky-ui";
import { CLASS_ORDER, PROFILES, type TargetClass } from "./types";

export type BulkEdit =
  | { op: "add-tag"; tag: string }
  | { op: "remove-tag"; tag: string }
  | { op: "set-class"; value: Exclude<TargetClass, "deactivated"> }
  | { op: "set-class"; value: "deactivated"; reason: string }
  | { op: "set-profiles"; value: string[] };

type Props = {
  count: number;
  tagVocabulary: string[];
  selectedTags: string[];
  onApply: (edit: BulkEdit) => void;
  onClear: () => void;
};

export function BulkEditBar({
  count,
  tagVocabulary,
  selectedTags,
  onApply,
  onClear,
}: Props) {
  const [tag, setTag] = useState("");
  const [profiles, setProfiles] = useState<string[]>([]);
  const [targetClass, setTargetClass] = useState<TargetClass | "">("");
  const [reason, setReason] = useState("");

  const commitTag = (op: "add-tag" | "remove-tag") => {
    const t = tag.trim();
    if (!t) return;
    onApply({ op, tag: t });
    setTag("");
  };

  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-border bg-muted/40 px-3 py-2">
      <span className="text-sm font-medium">
        {count} selected
      </span>

      <span className="mx-1 h-5 w-px bg-border" />

      <input
        list="tag-vocabulary"
        value={tag}
        onChange={(e) => setTag(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && commitTag("add-tag")}
        placeholder="tag…"
        className="h-8 w-40 rounded-md border border-input bg-background px-2 text-sm text-foreground"
      />
      <datalist id="tag-vocabulary">
        {tagVocabulary.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>
      <Button size="sm" variant="outline" onClick={() => commitTag("add-tag")}>
        + Add tag
      </Button>
      <Button size="sm" variant="outline" onClick={() => commitTag("remove-tag")}>
        − Remove tag
      </Button>

      {selectedTags.length > 0 && (
        <MultiSelect
          className="w-52"
          placeholder="Remove existing tag…"
          value={[]}
          options={selectedTags.map((t) => ({ value: t, label: t }))}
          onChange={(next) => {
            const t = next[next.length - 1];
            if (t) onApply({ op: "remove-tag", tag: t });
          }}
        />
      )}

      <span className="mx-1 h-5 w-px bg-border" />

      <Select
        className="w-36"
        placeholder="Set class…"
        value={targetClass}
        options={CLASS_ORDER.map((c) => ({ value: c, label: c }))}
        onChange={(e) => {
          const v = e.target.value as TargetClass;
          setTargetClass(v);
          if (v && v !== "deactivated") onApply({ op: "set-class", value: v });
        }}
      />

      {targetClass === "deactivated" ? (
        <>
          <input
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Deactivation reason…"
            aria-label="Deactivation reason"
            className="h-8 w-56 rounded-md border border-input bg-background px-2 text-sm text-foreground"
          />
          <Button
            size="sm"
            variant="outline"
            disabled={!reason.trim()}
            onClick={() => onApply({ op: "set-class", value: "deactivated", reason: reason.trim() })}
          >
            Deactivate
          </Button>
        </>
      ) : null}

      <MultiSelect
        className="w-40"
        placeholder="Set profiles…"
        value={profiles}
        options={PROFILES.map((p) => ({ value: p, label: p }))}
        onChange={(next) => {
          setProfiles(next);
          onApply({ op: "set-profiles", value: next });
        }}
      />

      <span className="flex-1" />
      <Button size="sm" variant="ghost" onClick={onClear}>
        Clear selection
      </Button>
    </div>
  );
}
