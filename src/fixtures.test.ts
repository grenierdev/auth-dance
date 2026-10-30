// This file exports fixtures the test files share. It holds no test, and vitest.config.ts leaves it out.
import { generateSigningKey } from "./keys.ts";

/** The issuer of every test instance. `http:` passes for `localhost`. */
export const TEST_ISSUER = "http://localhost";

/** One ES256 key. Each test file that imports it generates it one time, so the suites stay fast. */
export const TEST_SIGNING_KEYS = [await generateSigningKey()];
