import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  base: "/opendr/",
  root: "site",
  plugins: [react()],
  build: {
    outDir: "../build",
    emptyOutDir: true,
    chunkSizeWarningLimit: 700,
  },
});
