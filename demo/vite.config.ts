import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { devtools } from "@tanstack/devtools-vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import tailwindcss from "@tailwindcss/vite";
import path from "node:path";

// https://vite.dev/config/
export default defineConfig({
  //   resolve: { tsconfigPaths: true },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"), // Maps @ to the src directory
    },
  },
  plugins: [devtools(), tailwindcss(), tanstackStart(), react()],
});
