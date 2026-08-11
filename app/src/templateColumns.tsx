import type { DataTableColumn } from "@flanksource/clicky-ui";
import { SEVERITY_RANK, severityBadge } from "./scanColumns";
import type { Severity, Template } from "./types";

export const templateColumns: DataTableColumn<Template>[] = [
  {
    key: "severity",
    label: "Severity",
    sortable: true,
    filterable: true,
    shrink: true,
    render: (value) => severityBadge(value as Severity),
    sortValue: (value) => SEVERITY_RANK[value as Severity] ?? 9,
    filterValue: (value) => String(value),
  },
  {
    key: "name",
    label: "Template",
    grow: true,
    sortable: true,
    render: (value, row) => (
      <div className="flex flex-col">
        <span className="font-medium text-foreground">{String(value) || row.id}</span>
        <code className="text-xs text-muted-foreground">{row.id}</code>
      </div>
    ),
  },
  { key: "type", label: "Protocol", sortable: true, filterable: true, shrink: true },
  {
    key: "tags",
    label: "Tags",
    kind: "tags",
    filterable: true,
    tags: { maxVisible: 3 },
  },
  {
    key: "maxRequests",
    label: "Requests",
    sortable: true,
    shrink: true,
    // The per-target request cost. Blank rather than zero when the template
    // does not declare one: zero would read as "free", and it is not known.
    render: (value) =>
      value ? <span className="tabular-nums text-xs">{String(value)}</span> : null,
  },
  {
    key: "path",
    label: "Path",
    grow: true,
    sortable: true,
    render: (value) => (
      <code className="text-xs text-muted-foreground">{String(value)}</code>
    ),
  },
];

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs font-semibold uppercase text-muted-foreground">
        {title}
      </span>
      {children}
    </div>
  );
}

export function TemplateDetail({ template }: { template: Template }) {
  return (
    <div className="flex flex-col gap-3 px-4 py-3 text-sm">
      {template.description && (
        <Section title="Description">
          <p className="whitespace-pre-wrap text-foreground">{template.description}</p>
        </Section>
      )}
      {template.requires?.length ? (
        <Section title="Requires">
          {/* Named as the options that enable them, so the answer to "why is
              this not in my profile" is the switch to turn on. */}
          <p className="text-foreground">
            Only runs when the profile enables{" "}
            {template.requires.map((option, index) => (
              <span key={option}>
                {index > 0 ? ", " : ""}
                <code className="rounded bg-muted/50 px-1 py-0.5 text-xs">{option}</code>
              </span>
            ))}
            .
          </p>
        </Section>
      ) : null}
      {template.remediation && (
        <Section title="Remediation">
          <p className="whitespace-pre-wrap text-foreground">{template.remediation}</p>
        </Section>
      )}
      {(template.cveId || template.cvssScore) && (
        <Section title="Classification">
          <p className="text-foreground">
            {template.cveId}
            {template.cveId && template.cvssScore ? " · " : ""}
            {template.cvssScore ? `CVSS ${template.cvssScore}` : ""}
          </p>
        </Section>
      )}
      {template.authors?.length ? (
        <Section title="Authors">
          <p className="text-foreground">{template.authors.join(", ")}</p>
        </Section>
      ) : null}
      {template.reference?.length ? (
        <Section title="References">
          <ul className="list-inside list-disc text-xs">
            {template.reference.map((r) => (
              <li key={r}>
                <a href={r} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                  {r}
                </a>
              </li>
            ))}
          </ul>
        </Section>
      ) : null}
    </div>
  );
}
