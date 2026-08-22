// Export a run as a document.
//
// A menu rather than a button because the useful exports are not one thing: a
// PDF to attach to a ticket, the HTML behind it, the JSON the template renders,
// and the playground for when the default design is not the one this audience
// needs. All four are the same payload — see internal/httpapi/scanreport.go.

import { DropdownMenu } from "@flanksource/clicky-ui/components";

import { reportDataUrl, reportUrl } from "./scan-report";
import type { Scan } from "./types";

export function ScanExportMenu({
  scan,
  onOpenPlayground,
}: {
  scan: Scan | null;
  onOpenPlayground: (id: string) => void;
}) {
  // Rendering is a navigation rather than a fetch: the document can take tens of
  // seconds on a cold renderer, and the browser's own download UI reports that
  // better than a spinner this component would have to invent.
  const open = (href: string) => window.open(href, "_blank", "noopener");

  return (
    <DropdownMenu
      variant="outline"
      size="sm"
      label="Export"
      items={
        scan
          ? [
              {
                group: "Report",
                label: "PDF",
                title: "Render the report through facet",
                onSelect: () => open(reportUrl(scan.id, "pdf")),
              },
              {
                group: "Report",
                label: "HTML",
                title: "The same report as a self-contained page",
                onSelect: () => open(reportUrl(scan.id, "html")),
              },
              {
                group: "Report",
                label: "Design in playground…",
                title: "Tune the report against this run and export from there",
                onSelect: () => onOpenPlayground(scan.id),
              },
              {
                group: "Data",
                label: "Report payload (JSON)",
                title: "What the report template is rendered from",
                onSelect: () => open(reportDataUrl(scan.id)),
              },
            ]
          : []
      }
    />
  );
}
