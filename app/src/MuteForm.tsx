import { useMemo, useState } from "react";
import { Button } from "@flanksource/clicky-ui/components";
import { MuteTargets } from "./MuteTargets";
import { SEVERITIES } from "./types";
import { MUTE_DIMENSIONS, muteSelects } from "./mute-types";
import type { MutePreview, MuteRule } from "./mute-types";

type Props = {
  rule: MuteRule;
  /** Engine names offered, from the scan registry rather than a fixed list. */
  engines: string[];
  isNew: boolean;
  busy: boolean;
  preview: MutePreview | null;
  previewing: boolean;
  onChange: (rule: MuteRule) => void;
  onSave: () => void;
  onDelete: () => void;
  onPreview: () => void;
};

/** How each dimension is described where someone is deciding what to type. */
const DIMENSION_HELP: Record<(typeof MUTE_DIMENSIONS)[number], { label: string; hint: string }> = {
  templates: {
    label: "Checks",
    hint: "Template or check ids. Globs allowed — gcp/bucket_* matches every bucket check.",
  },
  resources: {
    label: "Resources",
    hint: "The thing a finding is about: a bucket uid, a URL, a hostname. Globs allowed.",
  },
  tags: {
    label: "Tags",
    hint: "Tags the finding carries. Prefix with ! to exclude — redirect, !dos.",
  },
  severity: {
    label: "Severity",
    hint: "",
  },
};

/** Splits the comma-separated form a list field is edited as. */
function toList(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "");
}

export function MuteForm({
  rule,
  engines,
  isNew,
  busy,
  preview,
  previewing,
  onChange,
  onSave,
  onDelete,
  onPreview,
}: Props) {
  const set = (patch: Partial<MuteRule>) => onChange({ ...rule, ...patch });
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  // Mirrors the server's own rule so the form can say why a rule cannot be
  // saved before asking, rather than round-tripping to find out.
  const selects = useMemo(() => muteSelects(rule), [rule]);
  const nameValid = /^[a-z0-9][a-z0-9-]*$/.test(rule.name);
  const canSave = nameValid && selects && !busy;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field
          label="Name"
          hint={
            isNew
              ? "Named after what the rule covers. Edit it if you would recognise something else in a run's mutes.json."
              : "Cited in each run's mutes.json, so it cannot change once the rule exists."
          }
        >
          <input
            className="w-full rounded border border-border bg-background px-2 py-1 text-sm disabled:opacity-60"
            value={rule.name}
            disabled={!isNew}
            aria-label="Name"
            onChange={(event) => set({ name: event.target.value })}
          />
          {isNew && rule.name !== "" && !nameValid && (
            <p className="mt-1 text-xs text-destructive">
              Use lowercase letters, digits and dashes, starting with a letter or digit.
            </p>
          )}
        </Field>

        <Field label="Comment" hint="Optional. Why this was accepted.">
          <input
            className="w-full rounded border border-border bg-background px-2 py-1 text-sm"
            value={rule.comment ?? ""}
            aria-label="Comment"
            onChange={(event) => set({ comment: event.target.value })}
          />
        </Field>
      </div>

      <Field
        label="Engines"
        hint="Which engines this rule is considered for. None selected means every engine. On its own it selects no finding."
      >
        <div className="flex flex-wrap gap-2">
          {engines.map((engine) => {
            const on = (rule.engines ?? []).includes(engine);
            return (
              <button
                key={engine}
                type="button"
                aria-pressed={on}
                onClick={() =>
                  set({
                    engines: on
                      ? (rule.engines ?? []).filter((name) => name !== engine)
                      : [...(rule.engines ?? []), engine],
                  })
                }
                className={`rounded-full border px-2.5 py-0.5 text-xs ${
                  on
                    ? "border-primary bg-primary/10 text-primary"
                    : "border-border text-muted-foreground"
                }`}
              >
                {engine}
              </button>
            );
          })}
        </div>
      </Field>

      <fieldset className="rounded-md border border-border p-3">
        <legend className="px-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          What it matches
        </legend>
        <p className="mb-3 text-xs text-muted-foreground">
          Every filled row must match, and any value within a row will do. A row left empty is not
          part of the rule.
        </p>

        <div className="grid gap-3">
          {MUTE_DIMENSIONS.filter((dimension) => dimension !== "severity").map((dimension) => (
            <Field
              key={dimension}
              label={DIMENSION_HELP[dimension].label}
              hint={DIMENSION_HELP[dimension].hint}
            >
              <input
                className="w-full rounded border border-border bg-background px-2 py-1 font-mono text-xs"
                value={(rule[dimension] ?? []).join(", ")}
                aria-label={DIMENSION_HELP[dimension].label}
                placeholder="comma separated"
                onChange={(event) => set({ [dimension]: toList(event.target.value) })}
              />
            </Field>
          ))}

          <MuteTargets
            targets={rule.targets}
            onChange={(targets) => set({ targets })}
          />

          <Field label="Severity" hint="">
            <div className="flex flex-wrap gap-2">
              {SEVERITIES.map((severity) => {
                const on = (rule.severity ?? []).includes(severity);
                return (
                  <button
                    key={severity}
                    type="button"
                    aria-pressed={on}
                    onClick={() =>
                      set({
                        severity: on
                          ? (rule.severity ?? []).filter((value) => value !== severity)
                          : [...(rule.severity ?? []), severity],
                      })
                    }
                    className={`rounded-full border px-2.5 py-0.5 text-xs ${
                      on
                        ? "border-primary bg-primary/10 text-primary"
                        : "border-border text-muted-foreground"
                    }`}
                  >
                    {severity}
                  </button>
                );
              })}
            </div>
          </Field>
        </div>
      </fieldset>

      <Field
        label="Expression"
        hint="Optional CEL over a single finding variable, e.g. finding.raw.resources[0].uid.startsWith(&quot;logs-&quot;). It narrows the rows above and can never widen them."
      >
        <textarea
          className="h-20 w-full rounded border border-border bg-background px-2 py-1 font-mono text-xs"
          value={rule.expr ?? ""}
          aria-label="Expression"
          onChange={(event) => set({ expr: event.target.value })}
        />
      </Field>

      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={rule.disabled ?? false}
          onChange={(event) => set({ disabled: event.target.checked })}
        />
        Disabled — kept, but not applied to any run
      </label>

      {!selects && (
        <p role="alert" className="text-xs text-destructive">
          This rule selects nothing. Fill at least one of the rows above or write an expression —
          a rule with no scope would mute every finding.
        </p>
      )}

      {/* Preview is the only way to see a rule's reach: a rule in force drops
          what it matches rather than marking it, so once it is saved there is
          nothing left to inspect. */}
      <div className="rounded-md border border-border bg-muted/20 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" disabled={isNew || previewing} onClick={onPreview}>
            {previewing ? "Checking…" : "What would this hide?"}
          </Button>
          {isNew && (
            <span className="text-xs text-muted-foreground">Save the rule before checking it.</span>
          )}
          {preview && !previewing && (
            <span className="text-xs text-muted-foreground">
              Matches <strong>{preview.matched.toLocaleString()}</strong> of{" "}
              {preview.examined.toLocaleString()} recorded findings.
              {preview.matched === 0 && " Nothing recorded would have been hidden."}
            </span>
          )}
        </div>
        {preview?.errors?.length ? (
          <p role="alert" className="mt-2 text-xs text-destructive">
            The expression could not be evaluated, so this rule would mute nothing:{" "}
            {preview.errors[0]}
          </p>
        ) : null}
        {preview && preview.matched > 0 && (
          <ul className="mt-2 max-h-40 overflow-y-auto text-xs">
            {preview.findings.slice(0, 20).map((finding) => (
              <li key={`${finding.scanId}#${finding.lineNo}`} className="flex gap-2 py-0.5">
                <span className="w-16 shrink-0 text-muted-foreground">{finding.severity}</span>
                <code className="truncate">{finding.templateId}</code>
                <span className="truncate text-muted-foreground">{finding.host}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button disabled={!canSave} onClick={onSave}>
          {isNew ? "Create rule" : "Save"}
        </Button>
        {!isNew &&
          (confirmingDelete ? (
            <>
              {/* Deleting stops the rule applying to future runs; it does not
                  bring back what earlier runs dropped, because those findings
                  were never recorded. Worth saying before the click, not
                  after. */}
              <span className="text-xs text-muted-foreground">
                Delete <strong>{rule.name}</strong>? Future runs will report these findings
                again. Runs that already dropped them are unchanged.
              </span>
              <Button variant="destructive" disabled={busy} onClick={onDelete}>
                Delete
              </Button>
              <Button
                variant="secondary"
                disabled={busy}
                onClick={() => setConfirmingDelete(false)}
              >
                Cancel
              </Button>
            </>
          ) : (
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() => setConfirmingDelete(true)}
            >
              Delete
            </Button>
          ))}
      </div>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div className="mb-1 text-xs font-medium">{label}</div>
      {children}
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
