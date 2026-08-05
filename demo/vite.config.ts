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
