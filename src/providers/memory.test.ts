import { testIdentityProvider, testKvProvider } from "../provider.test.ts";
import { describe } from "@std/testing/bdd";
import { MemoryIdentityProvider, MemoryKvProvider } from "./memory.ts";

describe("Memory provider", () => {
	testIdentityProvider(() => new MemoryIdentityProvider());
	testKvProvider(() => new MemoryKvProvider());
});
