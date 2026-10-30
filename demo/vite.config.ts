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
	plugins: [tanstackStart({ spa: { enabled: true } }), viteReact(), tailwindcss()],
});
