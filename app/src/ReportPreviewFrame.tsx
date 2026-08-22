// The report preview, rendered into an iframe.
//
// An iframe rather than a div because the preview has to be wrong in none of the
// ways a shared document would make it wrong: the report is styled by facet's
// stylesheet and its own Tailwind build, the app is styled by clicky-ui, and a
// single document would apply both to both. Inside the frame the report is the
// only thing there is — which is also what it will be in the PDF.

import { useEffect, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";

// `?inline` hands back the compiled CSS as a string, so neither stylesheet is
// ever linked into the app's own document.
import facetStyles from "@flanksource/facet/styles.css?inline";
import previewStyles from "./report-preview.css?inline";

// A4 at 96dpi. The frame is laid out at page width and scaled, rather than being
// given the pane's width: a preview that reflows to the pane would show line
// breaks the printed page will not have, which is the one thing it exists to
// get right.
const PAGE_WIDTH = 794;

export type PreviewZoom = 50 | 75 | 100;

export function ReportPreviewFrame({
  children,
  zoom,
  title,
}: {
  children: ReactNode;
  zoom: PreviewZoom;
  title: string;
}) {
  const frame = useRef<HTMLIFrameElement>(null);
  const [mount, setMount] = useState<HTMLElement | null>(null);
  const [height, setHeight] = useState(1123);

  useEffect(() => {
    const document_ = frame.current?.contentDocument;
    if (!document_) return;

    document_.head.replaceChildren();
    for (const css of [facetStyles, previewStyles]) {
      const style = document_.createElement("style");
      style.textContent = css;
      document_.head.appendChild(style);
    }
    document_.body.replaceChildren();
    setMount(document_.body);
  }, []);

  // The frame has no intrinsic height — it is a viewport onto a document that
  // grows — so it is measured and resized as the report changes. Without this
  // the preview would scroll inside a fixed box while the page it is previewing
  // is many pages long.
  useEffect(() => {
    if (!mount) return;
    const measure = () => setHeight(Math.max(mount.scrollHeight, 1123));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(mount);
    return () => observer.disconnect();
  }, [mount, children]);

  const scale = zoom / 100;
  return (
    <div className="h-full overflow-auto bg-muted/40 p-4">
      <div
        className="mx-auto bg-white shadow-sm"
        style={{ width: PAGE_WIDTH * scale, height: height * scale }}
      >
        <iframe
          ref={frame}
          title={title}
          className="border-0"
          style={{
            width: PAGE_WIDTH,
            height,
            transform: `scale(${scale})`,
            transformOrigin: "top left",
          }}
        >
          {/* React renders nothing here; the portal below fills the frame. */}
        </iframe>
        {mount && createPortal(children, mount)}
      </div>
    </div>
  );
}
