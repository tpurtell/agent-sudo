import { defineConfig } from "vite";

// In development, run the service locally and proxy the API to it:
//   AGENT_SUDO_API=http://127.0.0.1:8080 npm run dev
export default defineConfig({
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": { target: process.env.AGENT_SUDO_API ?? "http://127.0.0.1:8080", changeOrigin: false },
    },
  },
});
