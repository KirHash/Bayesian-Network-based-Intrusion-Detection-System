import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// In dev, the Vite server proxies the API and websocket to FastAPI
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/ws": { target: "ws://127.0.0.1:8000", ws: true }
    }
  },
  test: {
    environment: "jsdom",
    setupFiles: ["tests/setup.js"],
    include: ["tests/**/*.test.{js,jsx}"]
  }
});
