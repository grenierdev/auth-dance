import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["src/**/*.test.ts"],
		// provider.test.ts exports shared provider suites; the concrete providers register them. fixtures.test.ts exports
		// shared fixtures.
		exclude: ["src/provider.test.ts", "src/fixtures.test.ts"],
		environment: "node",
	},
});
