import type { DataTableColumn } from "@flanksource/clicky-ui/data";
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
    key: "engine",
    label: "Engine",
    sortable: true,
    filterable: true,
    shrink: true,
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
  {
    key: "provider",
    label: "Provider",
    sortable: true,
    filterable: true,
    shrink: true,
  },
  {
    key: "resourceType",
    label: "Resource",
    sortable: true,
    filterable: true,
    grow: true,
  },
  {
    key: "type",
    label: "Service / protocol",
    sortable: true,
    filterable: true,
    shrink: true,
  },
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

export function visibleTemplateColumns(
  templates: Template[],
  options: { itemLabel?: string; showEngine?: boolean } = {},
): DataTableColumn<Template>[] {
  const hasProvider = templates.some((template) => template.provider);
  const hasResource = templates.some((template) => template.resourceType);
  return templateColumns.filter(
    (column) =>
      (column.key !== "engine" || options.showEngine) &&
      (column.key !== "provider" || hasProvider) &&
      (column.key !== "resourceType" || hasResource),
  ).map((column) =>
    column.key === "name" && options.itemLabel
      ? { ...column, label: options.itemLabel.charAt(0).toUpperCase() + options.itemLabel.slice(1) }
      : column,
  );
}

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
  const metadata = template.metadata;
  const structuredRemediation = metadata?.remediation;
  const remediationText = structuredRemediation?.text ?? template.remediation;
  return (
    <div className="flex flex-col gap-3 px-4 py-3 text-sm">
      {template.description && (
        <Section title="Description">
          <p className="whitespace-pre-wrap text-foreground">{template.description}</p>
        </Section>
      )}
      {template.risk ? (
        <Section title="Risk">
          <p className="whitespace-pre-wrap text-foreground">{template.risk}</p>
        </Section>
      ) : null}
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
      {remediationText || structuredRemediation?.url || structuredRemediation?.code ? (
        <Section title="Remediation">
          {remediationText ? (
            <p className="whitespace-pre-wrap text-foreground">{remediationText}</p>
          ) : null}
          {structuredRemediation?.url ? (
            <a
              href={structuredRemediation.url}
              target="_blank"
              rel="noreferrer"
              className="text-primary hover:underline"
            >
              {structuredRemediation.url}
            </a>
          ) : null}
          {Object.entries(structuredRemediation?.code ?? {}).map(([name, code]) => (
            <div key={name} className="flex flex-col gap-1">
              <span className="text-xs text-muted-foreground">{name}</span>
              <code className="whitespace-pre-wrap rounded bg-muted/50 px-2 py-1 text-xs">
                {code}
              </code>
            </div>
          ))}
        </Section>
      ) : null}
      {metadata?.aliases?.length ? (
        <Section title="Aliases">
          <p className="text-foreground">{metadata.aliases.join(", ")}</p>
        </Section>
      ) : null}
      {metadata?.subService || metadata?.resourceGroup || metadata?.resourceIdTemplate ? (
        <Section title="Resource identifiers">
          <dl className="grid gap-x-3 gap-y-1 sm:grid-cols-[max-content_1fr]">
            {metadata.subService ? (
              <>
                <dt className="text-muted-foreground">Subservice</dt>
                <dd>{metadata.subService}</dd>
              </>
            ) : null}
            {metadata.resourceGroup ? (
              <>
                <dt className="text-muted-foreground">Resource group</dt>
                <dd>{metadata.resourceGroup}</dd>
              </>
            ) : null}
            {metadata.resourceIdTemplate ? (
              <>
                <dt className="text-muted-foreground">Resource ID</dt>
                <dd>
                  <code className="text-xs">{metadata.resourceIdTemplate}</code>
                </dd>
              </>
            ) : null}
          </dl>
        </Section>
      ) : null}
      {metadata?.categories?.length ? (
        <Section title="Categories">
          <p className="text-foreground">{metadata.categories.join(", ")}</p>
        </Section>
      ) : null}
      {metadata?.checkTypes?.length ? (
        <Section title="Check types">
          <p className="text-foreground">{metadata.checkTypes.join(", ")}</p>
        </Section>
      ) : null}
      {metadata?.dependsOn?.length ? (
        <Section title="Dependencies">
          <p className="text-foreground">{metadata.dependsOn.join(", ")}</p>
        </Section>
      ) : null}
      {metadata?.relatedTo?.length ? (
        <Section title="Related checks">
          <p className="text-foreground">{metadata.relatedTo.join(", ")}</p>
        </Section>
      ) : null}
      {metadata?.notes ? (
        <Section title="Notes">
          <p className="whitespace-pre-wrap text-foreground">{metadata.notes}</p>
        </Section>
      ) : null}
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
