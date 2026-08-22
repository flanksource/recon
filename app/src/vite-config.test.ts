import { describe, expect, it } from "vitest";

import { createViteConfig } from "../vite.config";

const localSourceAliases = [
  "@flanksource/clicky-ui",
  "@flanksource/clicky-ui/ai",
  "@flanksource/clicky-ui/chat",
  "@flanksource/clicky-ui/clicky",
  "@flanksource/clicky-ui/comments",
  "@flanksource/clicky-ui/components",
  "@flanksource/clicky-ui/data",
  "@flanksource/clicky-ui/hooks",
  "@flanksource/clicky-ui/icons",
  "@flanksource/clicky-ui/jotai",
  "@flanksource/clicky-ui/mdx-editor",
  "@flanksource/clicky-ui/mdx-editor.css",
  "@flanksource/clicky-ui/monaco",
  "@flanksource/clicky-ui/monaco/schema",
  "@flanksource/clicky-ui/profiles",
  "@flanksource/clicky-ui/rpc",
  "@flanksource/clicky-ui/styles.css",
  "@flanksource/clicky-ui/tailwind-preset",
  "@flanksource/clicky-ui/utils",
];

describe("createViteConfig", () => {
  it("aliases every clicky-ui runtime export for a local dev checkout", () => {
    const config = createViteConfig({
      command: "serve",
      mode: "development",
      clickySourceAvailable: true,
    });
    const aliases = Array.isArray(config.resolve?.alias)
      ? config.resolve.alias
      : [];

    expect({
      aliases: aliases.map(({ find }) =>
        find instanceof RegExp ? find.source.replaceAll("\\/", "/") : find,
      ),
      dedupe: config.resolve?.dedupe,
      fsAllow: config.server?.fs?.allow,
      optimizeDeps: config.optimizeDeps,
    }).toEqual({
      aliases: localSourceAliases.map(
        (entrypoint) => `^${entrypoint.replace(".", "\\.")}$`,
      ),
      dedupe: [
        "react",
        "react-dom",
        "react/jsx-runtime",
        "@tanstack/react-query",
        "@floating-ui/react",
      ],
      fsAllow: [
        expect.stringMatching(/\/recon\/app$/),
        expect.stringMatching(/\/flanksource\/clicky-ui\/packages\/ui$/),
      ],
      optimizeDeps: {
        exclude: ["@flanksource/clicky-ui"],
        force: true,
      },
    });
  });

  it.each([
    {
      name: "production build",
      command: "build" as const,
      mode: "production",
      clickySourceAvailable: true,
    },
    {
      name: "test mode",
      command: "serve" as const,
      mode: "test",
      clickySourceAvailable: true,
    },
    {
      name: "missing sibling checkout",
      command: "serve" as const,
      mode: "development",
      clickySourceAvailable: false,
    },
  ])("uses the pinned dependency for $name", (options) => {
    const config = createViteConfig(options);

    expect({
      alias: config.resolve?.alias,
      dedupe: config.resolve?.dedupe,
      fs: config.server?.fs,
      optimizeDeps: config.optimizeDeps,
    }).toEqual({
      alias: [],
      dedupe: [
        "react",
        "react-dom",
        "react/jsx-runtime",
        "@tanstack/react-query",
        "@floating-ui/react",
      ],
      fs: undefined,
      optimizeDeps: undefined,
    });
  });
});
