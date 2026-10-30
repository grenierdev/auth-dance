import { defineConfig } from "vite";

// The service worker builds on its own, into one classic script: `public/sw.js`. The app config serves `public/` at the
// root, so the worker sits at `/sw.js` and its scope covers every page.
export default defineConfig({
	publicDir: false,
	define: { "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV ?? "development") },
	build: {
		outDir: "public",
		emptyOutDir: false,
		sourcemap: true,
		minify: false,
		lib: { entry: "src/backend/sw.ts", formats: ["iife"], name: "authDanceDemoWorker", fileName: () => "sw.js" },
	},
});
