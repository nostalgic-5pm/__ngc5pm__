import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 40922,
    proxy: {
      '/api': {
        target: 'http://localhost:31113',
        changeOrigin: true,
      },
    },
  },
});
