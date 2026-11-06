import { fileURLToPath } from "node:url";
import contentCollections from "@content-collections/vite";
import tailwindcss from "@tailwindcss/vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
	resolve: {
		tsconfigPaths: true,
		alias: {
			// The landing page runs the real choreography DSL of the library, straight from its source.
			"@lib": fileURLToPath(new URL("../src", import.meta.url)),
		},
		dedupe: ["react", "react-dom"],
	},
	server: { fs: { allow: [".."] } },
	plugins: [
		contentCollections(),
		// Every page is prerendered to static HTML; `wrangler.jsonc` serves `dist/client`.
		// The llms.txt files are listed too, as no page links to them with a router `Link`.
		tanstackStart({ prerender: { enabled: true, crawlLinks: true, failOnError: true }, pages: [{ path: "/" }, { path: "/llms.txt" }, { path: "/llms-full.txt" }] }),
		viteReact(),
		tailwindcss(),
	],
});
