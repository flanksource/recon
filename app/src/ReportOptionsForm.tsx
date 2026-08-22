// The left pane of the report playground: every knob the printed report exposes.
//
// Each control writes one report option, and the options are the query string —
// so tuning a report here and exporting it from the scan page produce the same
// document, and a link to this page carries the design with it.

import { InputField, SegmentedControl, Switch } from "@flanksource/clicky-ui/components";

import { REPORT_SECTIONS, type ReportSectionKey } from "./scan-report";
import { SEVERITIES, type Severity } from "./types";
import type { ReportOptions } from "../reports/scan-report-types";

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-muted-foreground">{label}</span>
      {children}
      {hint && <span className="text-[11px] text-muted-foreground">{hint}</span>}
    </label>
  );
}

function Group({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-3">
      <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </h2>
      {children}
    </section>
  );
}

const TEXT_FIELDS: Array<{
  key: "title" | "subtitle" | "classification" | "preparedBy" | "audience" | "watermark";
  label: string;
  placeholder: string;
  hint?: string;
}> = [
  { key: "title", label: "Title", placeholder: "Scan Findings Report" },
  { key: "subtitle", label: "Subtitle", placeholder: "the run's name" },
  {
    key: "classification",
    label: "Classification",
    placeholder: "Internal",
    hint: "printed in the footer of every page",
  },
  { key: "preparedBy", label: "Prepared by", placeholder: "Security Engineering" },
  { key: "audience", label: "Audience", placeholder: "Platform Operations" },
  {
    key: "watermark",
    label: "Watermark",
    placeholder: "none",
    hint: "drawn diagonally across every page, e.g. DRAFT",
  },
];

export function ReportOptionsForm({
  options,
  onChange,
}: {
  options: ReportOptions;
  onChange: (next: ReportOptions) => void;
}) {
  const set = <K extends keyof ReportOptions>(key: K, value: ReportOptions[K]) =>
    onChange({ ...options, [key]: value });

  const setSection = (key: ReportSectionKey, enabled: boolean) =>
    onChange({ ...options, sections: { ...options.sections, [key]: enabled } });

  return (
    <div className="flex h-full flex-col gap-6 overflow-y-auto p-4">
      <Group title="Cover">
        {TEXT_FIELDS.map((field) => (
          <Field key={field.key} label={field.label} hint={field.hint}>
            <InputField
              value={options[field.key] ?? ""}
              placeholder={field.placeholder}
              onChange={(value) => set(field.key, value)}
            />
          </Field>
        ))}
        <Field label="Scope" hint="one line describing what the run covered">
          <InputField
            as="textarea"
            rows={3}
            value={options.scope ?? ""}
            placeholder="Unauthenticated scan of every internet-facing host in the production class."
            onChange={(value) => set("scope", value)}
          />
        </Field>
      </Group>

      <Group title="What to print">
        <Field
          label="Lowest severity included"
          hint="the severity totals stay whole-run, and the report says what it excluded"
        >
          <SegmentedControl
            size="sm"
            wrap
            aria-label="Lowest severity included"
            value={options.minSeverity ?? "all"}
            options={[
              { id: "all", label: "All" },
              ...SEVERITIES.filter((severity) => severity !== "unknown").map((severity) => ({
                id: severity,
                label: severity,
              })),
            ]}
            onChange={(id) =>
              set("minSeverity", id === "all" ? undefined : (id as Severity))
            }
          />
        </Field>
        <Field
          label="Detailed findings"
          hint="0 prints evidence for every finding; the summary table always lists them all"
        >
          <InputField
            type="number"
            min={0}
            value={String(options.maxDetailedFindings ?? 0)}
            onChange={(value) => {
              const parsed = Number(value);
              set(
                "maxDetailedFindings",
                Number.isFinite(parsed) && parsed > 0 ? parsed : undefined,
              );
            }}
          />
        </Field>
      </Group>

      <Group title="Sections">
        {REPORT_SECTIONS.map((section) => (
          <Switch
            key={section.key}
            label={section.label}
            checked={options.sections?.[section.key] !== false}
            onChange={(enabled) => setSection(section.key, enabled)}
          />
        ))}
      </Group>
    </div>
  );
}
