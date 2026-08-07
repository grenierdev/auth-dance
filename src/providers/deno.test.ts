import { testIdentityProvider, testKvProvider } from "../provider.test.ts";
import { describe } from "@std/testing/bdd";
import { DenoIdentityProvider, DenoKvProvider } from "./deno.ts";

describe("Deno provider", () => {
	testIdentityProvider(async () => new DenoIdentityProvider(await Deno.openKv(":memory:")));
	testKvProvider(async () => new DenoKvProvider(await Deno.openKv(":memory:")));
});
