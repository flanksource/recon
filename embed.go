// Package recon embeds the built web interface so `reconctl serve` is a single
// binary with no runtime dependency on a checkout.
//
// app/dist is committed with a .gitkeep because the pattern must match
// something for the package to compile on a fresh clone; the SPA handler
// reports a missing index.html as "run pnpm build" rather than failing here.
package recon

import "embed"

//go:embed all:app/dist
var UI embed.FS

// UIDir is the path within UI that the built app lives at.
const UIDir = "app/dist"

// ReportSource is the facet template the scan report is printed from.
//
// The same TSX is mounted by the in-app report playground, which is why it lives
// under app/ rather than beside the Go that renders it: vite resolves its
// `@flanksource/facet` import out of app/node_modules, and one template rendered
// two ways cannot drift. The patterns are explicit rather than `all:app/reports`
// because a render in a checkout leaves node_modules and dist beside the source,
// and neither belongs in the binary.
//
//go:embed app/reports/*.tsx app/reports/*.ts app/reports/package.json
var ReportSource embed.FS

// ReportSourceDir is the path within ReportSource that the template lives at.
const ReportSourceDir = "app/reports"

// ReportEntry is the template file facet renders.
const ReportEntry = "ScanReport.tsx"
