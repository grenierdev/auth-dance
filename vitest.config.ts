import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["src/**/*.test.ts"],
		// This file exports shared provider suites; the concrete providers register them.
		exclude: ["src/provider.test.ts"],
		environment: "node",
	},
});
