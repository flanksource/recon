import { existsSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  defineConfig,
  type ConfigEnv,
  type Plugin,
  type UserConfig,
} from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const clickyUIRoot = resolve(
  import.meta.dirname,
  "../../clicky-ui/packages/ui",
);
const clickyUISource = resolve(clickyUIRoot, "src");
const clickyUIEntrypoints = [
  ["@flanksource/clicky-ui", "index.ts"],
  ["@flanksource/clicky-ui/ai", "ai.ts"],
  ["@flanksource/clicky-ui/chat", "chat.ts"],
  ["@flanksource/clicky-ui/clicky", "clicky.ts"],
  ["@flanksource/clicky-ui/comments", "comments.ts"],
  ["@flanksource/clicky-ui/components", "components.ts"],
  ["@flanksource/clicky-ui/data", "data.ts"],
  ["@flanksource/clicky-ui/hooks", "hooks.ts"],
  ["@flanksource/clicky-ui/icons", "icons.ts"],
  ["@flanksource/clicky-ui/jotai", "jotai.ts"],
  ["@flanksource/clicky-ui/mdx-editor", "mdx-editor.ts"],
  ["@flanksource/clicky-ui/mdx-editor.css", "styles/mdx-editor.css"],
  ["@flanksource/clicky-ui/monaco", "monaco.ts"],
  ["@flanksource/clicky-ui/monaco/schema", "monaco-schema.ts"],
  ["@flanksource/clicky-ui/profiles", "profiles.ts"],
  ["@flanksource/clicky-ui/rpc", "rpc.ts"],
  ["@flanksource/clicky-ui/styles.css", "styles/full.css"],
  ["@flanksource/clicky-ui/tailwind-preset", "tailwind-preset.ts"],
  ["@flanksource/clicky-ui/utils", "utils.ts"],
] as const;
const sharedDependencies = [
  "react",
  "react-dom",
  "react/jsx-runtime",
  "@tanstack/react-query",
  "@floating-ui/react",
];

type ViteConfigOptions = {
  command: ConfigEnv["command"];
  mode: string;
  clickySourceAvailable: boolean;
};

// The Go binary embeds app/dist with `//go:embed all:app/dist`, and an embed
// that matches nothing is a compile error — so the directory has to exist even
// on a checkout that has never run a build. A tracked .gitkeep covers that, but
// emptying the output directory deletes it, which would break the Go build the
// first time anyone ran `vite build`.
function keepDistTracked(): Plugin {
  return {
    name: "recon:keep-dist-tracked",
    apply: "build",
    closeBundle() {
      writeFileSync(resolve(import.meta.dirname, "dist/.gitkeep"), "");
    },
  };
}

export function createViteConfig({
  command,
  mode,
  clickySourceAvailable,
}: ViteConfigOptions): UserConfig {
  const useClickySource =
    command === "serve" && mode !== "test" && clickySourceAvailable;

  return {
    plugins: [react(), tailwindcss(), keepDistTracked()],
    resolve: {
      alias: useClickySource
        ? clickyUIEntrypoints.map(([entrypoint, source]) => ({
            find: new RegExp(
              `^${entrypoint.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`,
            ),
            replacement: resolve(clickyUISource, source),
          }))
        : [],
      dedupe: sharedDependencies,
    },
    optimizeDeps: useClickySource
      ? {
          exclude: ["@flanksource/clicky-ui"],
          force: true,
        }
      : undefined,
    server: {
      port: 5280,
      strictPort: true,
      ...(useClickySource
        ? { fs: { allow: [import.meta.dirname, clickyUIRoot] } }
        : {}),
      proxy: {
        "/api": {
          target: "http://localhost:8280",
          changeOrigin: true,
          // The scan event stream must reach the browser frame by frame. Without
          // this the proxy buffers the response and the UI sits idle until the
          // scan ends, which looks exactly like a hung run.
          configure: (proxy) => {
            proxy.on("proxyRes", (proxyRes) => {
              if (
                proxyRes.headers["content-type"]?.includes("text/event-stream")
              ) {
                delete proxyRes.headers["content-length"];
              }
            });
          },
        },
      },
    },
    preview: {
      port: 5280,
      strictPort: true,
    },
  };
}

export default defineConfig(({ command, mode }) =>
  createViteConfig({
    command,
    mode,
    clickySourceAvailable: existsSync(clickyUISource),
  }),
);
