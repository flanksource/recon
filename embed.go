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
