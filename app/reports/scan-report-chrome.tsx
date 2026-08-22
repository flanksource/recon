// The primitives every block on the printed page is built from.
//
// Two rules govern everything here, and both come from the renderer rather than
// from taste:
//
//   - Sizes are written in points and millimetres, never in `text-sm` or `px`.
//     facet's stylesheet redefines the named type scale in points inside an
//     `@media print` block, so `text-2xl` is 24pt on paper and 24px in the
//     playground iframe — a size that only agrees with itself in one of the two
//     places the report is looked at.
//   - Borders, never rings. The PDF is compiled against Tailwind 3, whose
//     default ring colour is blue; a `ring-1` copied from a screen surface
//     prints a blue halo around every tile.

import type { ReactNode } from "react";
import { Fragment } from "react";

import type { TagStyle } from "./scan-report-tags";

/** Sizes are a lookup rather than a template — the scanner only emits literal classes. */
const TILE = {
  xs: { frame: "h-[3.4mm] w-[3.4mm] rounded-[1mm]", glyph: "h-[2.2mm] w-[2.2mm]" },
  sm: { frame: "h-[4.2mm] w-[4.2mm] rounded-[1.2mm]", glyph: "h-[2.8mm] w-[2.8mm]" },
  md: { frame: "h-[5mm] w-[5mm] rounded-[1.2mm]", glyph: "h-[3mm] w-[3mm]" },
} as const;

/**
 * One idea, tiled: a soft surface in its hue with its glyph on top.
 *
 * `sm` is 4.2mm because that is the slot facet's ListTable gives a row icon; a
 * tile any larger is clipped in the breakdown columns.
 */
export function KindTile({ style, size = "xs" }: { style: TagStyle; size?: keyof typeof TILE }) {
  const Glyph = style.icon;
  return (
    <span
      className={`grid shrink-0 place-items-center border ${TILE[size].frame} ${style.className}`}
    >
      <Glyph className={TILE[size].glyph} />
    </span>
  );
}

/** The muted middot run every secondary fact rides in. */
export function Facts({ items }: { items: ReactNode[] }) {
  const present = items.filter((item) => item != null && item !== false && item !== "");
  return (
    <span className="min-w-0 text-[8pt] leading-[11pt] text-gray-500">
      {present.map((item, index) => (
        <Fragment key={index}>
          {index > 0 && <span aria-hidden="true"> · </span>}
          {item}
        </Fragment>
      ))}
    </span>
  );
}

/**
 * A section heading. Block, because facet's print typography renders h2/h3
 * inline-flex; and the same 7pt tracked uppercase the page header and the run
 * table's column headers use, so the page speaks with one voice.
 */
export function SectionHeading({ children }: { children: ReactNode }) {
  return (
    <h2
      className="mb-[2.5mm] block border-b border-gray-200 pb-[1mm] text-[7pt] font-semibold uppercase tracking-[0.08em] text-gray-500"
      style={{ breakAfter: "avoid" }}
    >
      {children}
    </h2>
  );
}

export function PageHeading({ children }: { children: ReactNode }) {
  return (
    <h2
      className="mb-[4mm] block border-b border-gray-200 pb-[2mm] text-[15pt] font-bold leading-[19pt] text-gray-900"
      style={{ breakAfter: "avoid" }}
    >
      {children}
    </h2>
  );
}

/**
 * A grid whose column count is the number of cards.
 *
 * Tailwind's `grid-cols-N` classes cannot be built from a variable — the scanner
 * only sees literal class names — and a fixed four columns wrapped the severity
 * row onto a second line as soon as a run carried info-level findings.
 */
export function FixedGrid({ columns, children }: { columns: number; children: ReactNode }) {
  return (
    <div
      className="grid gap-[2.5mm]"
      style={{ gridTemplateColumns: `repeat(${Math.max(columns, 1)}, minmax(0, 1fr))` }}
    >
      {children}
    </div>
  );
}

/**
 * Four columns, unless that would strand a single card on its own row.
 *
 * Coverage is nine metrics for a compliance run and six for a network scan, and
 * a lone card under a full row reads as an afterthought rather than as one of
 * the set.
 */
export function balancedColumns(count: number): number {
  return count > 4 && count % 4 === 1 ? 3 : 4;
}
