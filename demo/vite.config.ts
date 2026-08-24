import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { devtools } from "@tanstack/devtools-vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import tailwindcss from "@tailwindcss/vite";
import deno from "@deno/vite-plugin";
import path from "node:path";

// The `deno` plugin resolves what Vite cannot: the `auth-dance` entries of `deno.jsonc`, which point straight at
// the TypeScript of the sibling library, and the `jsr:` specifiers that library imports.
// https://vite.dev/config/
export default defineConfig({
	resolve: {
		alias: {
			"@": path.resolve(import.meta.dirname!, "./src"), // Maps @ to the src directory
		},
	},
	plugins: [
		deno(),
		devtools(),
		tailwindcss(),
		tanstackStart({
			router: {
				// `addExtensions` makes the generated route tree import `./routes/__root.tsx` rather than the
				// extensionless form, which is the one form Deno's resolver reads. The header replaces the
				// generator's default, so the three lines it ships with are repeated here: without `@ts-nocheck`,
				// `noUnusedLocals` reports the `createStart` type import the generator writes but never uses.
				routeTreeFileHeader: [
					`// deno-lint-ignore-file`,
					`// deno-fmt-ignore-file`,
					`/* eslint-disable */`,
					`// @ts-nocheck`,
					`// noinspection JSUnusedGlobalSymbols`,
				],
				addExtensions: true,
			},
			prerender: {
				enabled: true,
				crawlLinks: true, // Crawls routes automatically
				onSuccess: () => {
					console.log("Prerendering complete. Forcing process exit...");
					process.exit(0); // Kills the hanging Node.js stream timeouts
				},
			},
		}),
		react(),
	],
});
