// Dump the TypeScript option catalogs so the Go port can be generated from them
// rather than retyped. Retyping ~1100 lines of flag metadata by hand guarantees
// typos, and a wrong `minimum` or a dropped enum value is invisible until
// someone opens the Profiles form.
//
//   pnpm --dir app exec tsx hack/dump-catalog.ts
//
// Writes ../internal/engines/testdata/catalog.json, which is both the codegen
// input and the fixture a Go test asserts the generated catalog still matches.
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { profileSections } from "../profile-schema/index.ts";

const out = resolve(import.meta.dirname, "..", "..", "internal", "engines", "testdata");
mkdirSync(out, { recursive: true });
writeFileSync(resolve(out, "catalog.json"), `${JSON.stringify(profileSections, null, 2)}\n`);

const summary = Object.fromEntries(
  Object.entries(profileSections).map(([engine, sections]) => [
    engine,
    {
      sections: sections.length,
      options: sections.reduce((total, section) => total + Object.keys(section.properties).length, 0),
    },
  ]),
);
console.log(JSON.stringify(summary, null, 2));
