import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// In real mode the React app and the API share one origin, so the dev server
// forwards /api to the FastAPI backend. This avoids CORS and keeps cookies simple.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET ?? "http://localhost:8000",
        changeOrigin: false,
      },
    },
  },
  test: {
    environment: "node",
  },
});
