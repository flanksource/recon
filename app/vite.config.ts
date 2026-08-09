import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

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

export default defineConfig({
  plugins: [react(), tailwindcss(), keepDistTracked()],
  server: {
    port: 5280,
    strictPort: true,
    proxy: {
      "/api": {
        target: "http://localhost:8280",
        changeOrigin: true,
        // The scan event stream must reach the browser frame by frame. Without
        // this the proxy buffers the response and the UI sits idle until the
        // scan ends, which looks exactly like a hung run.
        configure: (proxy) => {
          proxy.on("proxyRes", (proxyRes) => {
            if (proxyRes.headers["content-type"]?.includes("text/event-stream")) {
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
});
