/// <reference types="vite/client" />

// `?inline` hands back a stylesheet's compiled text instead of linking it into
// the document. The report preview injects both of these into an iframe, which
// is what keeps the report's styling and the app's from reaching each other —
// see ReportPreviewFrame.tsx.
declare module "*.css?inline" {
  const css: string;
  export default css;
}
