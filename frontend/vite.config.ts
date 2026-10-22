import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

// SR-09: the browser keeps no copy of the app's pages and files (the API sends the same header)
const noStore = { "Cache-Control": "no-store" };

// The React app and the API share one origin: the dev server forwards /api to
// the FastAPI backend. This avoids CORS and keeps cookies simple.
export default defineConfig(({ mode }) => {
  // The config file does not see frontend/.env on its own, so load it here
  const env = loadEnv(mode, process.cwd(), "VITE_");
  return {
    plugins: [react()],
    server: {
      port: 5173,
      headers: noStore, // SR-09
      proxy: {
        "/api": {
          // SR-10: the backend speaks only TLS 1.3, and the proxy checks its certificate as usual.
          // Start the dev server with NODE_EXTRA_CA_CERTS pointing at certs/dev-cert.pem (see README).
          target: env.VITE_API_TARGET || "https://localhost:8443",
          changeOrigin: false,
        },
      },
    },
    // SR-09: `vite preview` serves the built app with the same header
    preview: {
      headers: noStore,
    },
    // SR-06: two pages, the voter app and the staff sign-in page, so both are built
    build: {
      rollupOptions: {
        input: {
          main: fileURLToPath(new URL("index.html", import.meta.url)),
          staff: fileURLToPath(new URL("staff.html", import.meta.url)),
        },
      },
    },
    test: {
      environment: "node",
    },
  };
});
