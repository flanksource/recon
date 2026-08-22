import type { ComponentProps } from "react";
import Markdown, { type MarkdownToJSX } from "markdown-to-jsx";

function MarkdownImage({ alt }: ComponentProps<"img">) {
  return <span className="italic text-slate-500">{alt || "Image"}</span>;
}

const OPTIONS = {
  disableParsingRawHTML: true,
  forceBlock: true,
  overrides: {
    p: { props: { className: "mb-1.5 text-[8.5pt] leading-[12pt] text-slate-700 last:mb-0" } },
    ul: { props: { className: "mb-1.5 list-disc space-y-0.5 pl-5 text-[8.5pt] text-slate-700" } },
    ol: { props: { className: "mb-1.5 list-decimal space-y-0.5 pl-5 text-[8.5pt] text-slate-700" } },
    li: { props: { className: "pl-0.5 leading-[12pt]" } },
    a: {
      props: {
        className: "break-all font-medium text-blue-700 underline",
        rel: "noopener noreferrer",
        target: "_blank",
      },
    },
    code: {
      props: {
        className: "rounded bg-slate-100 px-1 py-0.5 font-mono text-[8pt] text-slate-800",
      },
    },
    pre: {
      props: {
        className: "my-2 overflow-hidden whitespace-pre-wrap rounded bg-slate-100 p-2 font-mono text-[7.5pt]",
      },
    },
    blockquote: {
      props: { className: "my-1.5 border-l-2 border-slate-300 pl-2 italic text-slate-600" },
    },
    h1: { props: { className: "mb-1 mt-2 text-[9pt] font-semibold text-slate-900 first:mt-0" } },
    h2: { props: { className: "mb-1 mt-2 text-[9pt] font-semibold text-slate-900 first:mt-0" } },
    h3: { props: { className: "mb-1 mt-2 text-[9pt] font-semibold text-slate-900 first:mt-0" } },
    h4: { props: { className: "mb-1 mt-2 text-[9pt] font-semibold text-slate-900 first:mt-0" } },
    h5: { props: { className: "mb-1 mt-2 text-[9pt] font-semibold text-slate-900 first:mt-0" } },
    h6: { props: { className: "mb-1 mt-2 text-[9pt] font-semibold text-slate-900 first:mt-0" } },
    table: { props: { className: "my-2 w-full border-collapse text-left text-[8pt] text-slate-700" } },
    th: { props: { className: "border border-slate-200 bg-slate-50 px-1.5 py-1 font-semibold" } },
    td: { props: { className: "border border-slate-200 px-1.5 py-1 align-top" } },
    img: { component: MarkdownImage },
  },
} satisfies MarkdownToJSX.Options;

export function ReportMarkdownSection({ title, values }: { title: string; values: string[] }) {
  if (!values.length) return null;
  return (
    <section className="mb-3 ml-4 break-inside-avoid border-l-2 border-slate-200 pl-3">
      <h4 className="mb-1 text-[8pt] font-bold uppercase tracking-wide text-slate-500">{title}</h4>
      <div className="divide-y divide-slate-100">
        {values.map((value) => (
          <div key={value} className="py-1 first:pt-0 last:pb-0">
            <Markdown options={OPTIONS}>{value}</Markdown>
          </div>
        ))}
      </div>
    </section>
  );
}
