import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { targetsApi } from "./vite-plugin-targets.ts";

export default defineConfig({
  plugins: [react(), tailwindcss(), targetsApi()],
  server: {
    port: 5280,
    strictPort: true,
  },
  preview: {
    port: 5280,
    strictPort: true,
  },
});
