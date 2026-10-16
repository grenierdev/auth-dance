import { deepEqual, rejects } from "node:assert";
import { describe, it } from "vitest";
import { generateKey, hotp, totp } from "./otp.ts";

describe("One Time Password", () => {
	it("generateKey", async () => {
		deepEqual((await generateKey()).length, 32);
		deepEqual((await generateKey(16)).length, 16);
		deepEqual((await generateKey(100)).length, 100);
	});

	it("hotp", async () => {
		const key = await generateKey();
		const c1 = await hotp({ counter: 1, key, digits: 6 });
		const c2 = await hotp({ counter: 1, key, digits: 6 });
		deepEqual(c1, c2);
		await rejects(() => hotp({ counter: 1, key: "foo", digits: 6 }));
	});

	it("totp", async () => {
		const key = await generateKey(48);
		const c1 = await totp({ time: 1, period: 30, key, digits: 6 });
		const c2 = await totp({ time: 1, period: 30, key, digits: 6 });
		deepEqual(c1, c2);
		await rejects(() => totp({ time: 1, period: 30, key: "foo", digits: 6 }));
	});
});
