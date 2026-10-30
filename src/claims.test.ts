import { deepEqual, ok, rejects } from "node:assert";
import { describe, it } from "vitest";
import { type AuthDanceClaimsContext, type AuthDanceScope, defaultClaims, RESERVED_CLAIMS, resolveClaims } from "./claims.ts";
import { ClaimsMapperError } from "./error.ts";
import type { AuthDanceIdentity } from "./identity.ts";

const identity: AuthDanceIdentity = {
	id: "id_1",
	data: { name: "Alice", email: "alice@example.com", locale: "fr-CA" },
	components: [],
};

const scopes: Record<string, AuthDanceScope> = {
	profile: { description: "Your name", claims: ["name", "locale"] },
	email: { description: { en: "Your email address", fr: "Votre adresse" }, claims: ["email"] },
	roles: { description: "Your roles" },
};

function context(overrides: Partial<Omit<AuthDanceClaimsContext, "defaults">> = {}): Omit<AuthDanceClaimsContext, "defaults"> {
	return {
		client_id: "cli_test",
		identity,
		subject: identity.id,
		scopes: ["profile"],
		session_id: "ses_1",
		grant_type: "authorization_code",
		target: "access_token",
		...overrides,
	};
}

async function mapperError(fn: () => Promise<unknown>, reason: RegExp): Promise<void> {
	await rejects(fn, (error) => error instanceof ClaimsMapperError && reason.test(String((error.cause as Error)?.message)));
}

describe("claims", () => {
	it("should map the data bag by the claims of each granted scope, without a mapper", async () => {
		deepEqual(await resolveClaims(context({ scopes: ["profile", "email", "roles"] }), scopes), {
			name: "Alice",
			locale: "fr-CA",
			email: "alice@example.com",
		});
		deepEqual(await resolveClaims(context(), scopes), { name: "Alice", locale: "fr-CA" });
	});
	it("should group the defaults by granted scope", () => {
		deepEqual(defaultClaims(identity, ["email", "roles", "unknown"], scopes), {
			email: { email: "alice@example.com" },
			roles: {},
			unknown: {},
		});
	});
	it("should drop the group of a scope that was not granted", async () => {
		const claims = await resolveClaims(context(), scopes, () => ({
			profile: { name: "Alice" },
			email: { email: "alice@example.com" },
		}));
		deepEqual(claims, { name: "Alice" });
	});
	it("should raise when two scopes give one claim two values, and accept the same value", async () => {
		const ctx = context({ scopes: ["profile", "email"] });
		await mapperError(() => resolveClaims(ctx, scopes, () => ({ profile: { tenant: "a" }, email: { tenant: "b" } })), /two values/);
		const same = { tenant: { id: 1, tags: ["x"] } };
		deepEqual(await resolveClaims(ctx, scopes, () => ({ profile: same, email: structuredClone(same) })), same);
	});
	it("should raise on a reserved claim name", async () => {
		for (const name of RESERVED_CLAIMS) {
			await mapperError(() => resolveClaims(context(), scopes, () => ({ profile: { [name]: "x" } })), /reserved/);
		}
	});
	it("should raise ClaimsMapperError when the mapper throws, with the failure as cause", async () => {
		const failure = new Error("tenant service down");
		await rejects(
			() =>
				resolveClaims(context(), scopes, () => {
					throw failure;
				}),
			(error) => error instanceof ClaimsMapperError && error.cause === failure && error.code === "CLAIMS_MAPPER_FAILED",
		);
		await rejects(() => resolveClaims(context(), scopes, () => Promise.reject(failure)), ClaimsMapperError);
	});
	it("should raise on a value that is not JSON or a group that is not an object", async () => {
		await mapperError(() => resolveClaims(context(), scopes, () => ({ profile: { at: new Date() } }) as never), /not JSON/);
		await mapperError(() => resolveClaims(context(), scopes, () => ({ profile: { n: Number.NaN } })), /not JSON/);
		await mapperError(() => resolveClaims(context(), scopes, () => ({ profile: ["x"] }) as never), /not an object/);
		await mapperError(() => resolveClaims(context(), scopes, () => null as never), /object of claim groups/);
	});
	it("should skip a claim the mapper leaves undefined", async () => {
		deepEqual(await resolveClaims(context(), scopes, () => ({ profile: { name: "Alice", nickname: undefined } as never })), {
			name: "Alice",
		});
	});
	it("should hand the mapper no identity for client credentials", async () => {
		let seen: AuthDanceClaimsContext | undefined;
		const claims = await resolveClaims(
			context({
				identity: undefined,
				subject: "cli_test",
				session_id: undefined,
				grant_type: "client_credentials",
				scopes: ["profile", "roles"],
			}),
			scopes,
			(ctx) => {
				seen = ctx;
				return { ...ctx.defaults, roles: { roles: ["reporter"] } };
			},
		);
		deepEqual(seen?.identity, undefined);
		deepEqual(seen?.defaults, { profile: {}, roles: {} });
		deepEqual(claims, { roles: ["reporter"] });
	});
	it("should hand client_id and the session to the mapper", async () => {
		let seen: AuthDanceClaimsContext | undefined;
		await resolveClaims(context(), scopes, (ctx) => {
			seen = ctx;
			return ctx.defaults;
		});
		deepEqual([seen?.client_id, seen?.session_id], ["cli_test", "ses_1"]);
		deepEqual(seen?.defaults, { profile: { name: "Alice", locale: "fr-CA" } });
	});
	it("should keep a claim named __proto__ as a plain key", async () => {
		const claims = await resolveClaims(context(), scopes, () => JSON.parse('{"profile":{"__proto__":{"polluted":true}}}'));
		ok(Object.hasOwn(claims, "__proto__"));
		deepEqual(({} as Record<string, unknown>).polluted, undefined);
	});
});
