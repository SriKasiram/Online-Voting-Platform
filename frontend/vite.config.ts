import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { loadEnv } from "vite";
import { defineConfig } from "vitest/config";

// The React app and the API share one origin: the dev server forwards /api to
// the FastAPI backend. This avoids CORS and keeps cookies simple.
export default defineConfig(({ mode }) => {
  // The config file does not see frontend/.env on its own, so load it here
  const env = loadEnv(mode, process.cwd(), "VITE_");
  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        "/api": {
          // 127.0.0.1 rather than localhost: on Windows, localhost can try IPv6 first and stall
          target: env.VITE_API_TARGET || "http://127.0.0.1:8000",
          changeOrigin: false,
        },
      },
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
