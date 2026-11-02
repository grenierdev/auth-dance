import tailwindcss from "@tailwindcss/vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// No proxy: the service worker of `src/backend/sw.ts`, served from `public/sw.js`, answers `/auth`, `/oauth2`,
// `/.well-known` and `/api` inside the browser.
export default defineConfig({
	resolve: {
		tsconfigPaths: true,
		// `auth-dance` links to the parent folder, which holds its own copy of React.
		dedupe: ["react", "react-dom"],
	},
	// The shell goes to `index.html`, which the `single-page-application` mode of `wrangler.jsonc` serves.
	plugins: [tanstackStart({ spa: { enabled: true, prerender: { outputPath: "/index" } } }), viteReact(), tailwindcss()],
});
