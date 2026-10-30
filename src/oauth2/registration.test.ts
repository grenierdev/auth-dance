import { deepEqual, ok, rejects } from "node:assert";
import { beforeEach, describe, it } from "vitest";
import { type TestIdp, testIdp } from "../fixtures.test.ts";
import type { AuthDanceOauth2ApiOptions } from "./api.ts";
import type { AuthDanceOauth2ClientPublic } from "./client.ts";
import { InvalidClientMetadataError } from "./error.ts";

const web = { redirect_uris: ["https://app.example.com/callback"], client_name: "App", "client_name#fr-CA": "Appli" };

describe("registerClient", () => {
	let env: TestIdp;
	let registered: AuthDanceOauth2ClientPublic[];

	function setup(options: Partial<AuthDanceOauth2ApiOptions> = {}): void {
		registered = [];
		env = testIdp({
			oauth2: {
				registration: { scope: ["profile", "email"] },
				hooks: {
					onClientRegistered: ({ client }) => {
						registered.push(client);
					},
				},
				...options,
			},
		});
	}

	beforeEach(() => {
		setup();
	});

	it("should answer every registered field, the defaults and the secret included", async () => {
		const answer = await env.idp.oauth2.registerClient({ ...web, scope: "profile reports" });
		ok(answer.client_id.startsWith("cli_"));
		ok(typeof answer.client_secret === "string" && answer.client_secret.length === 43);
		deepEqual(
			{ ...answer, client_id: "x", client_secret: "x", client_id_issued_at: 0 },
			{
				client_id: "x",
				client_secret: "x",
				client_id_issued_at: 0,
				client_secret_expires_at: 0,
				redirect_uris: ["https://app.example.com/callback"],
				token_endpoint_auth_method: "client_secret_basic",
				grant_types: ["authorization_code"],
				response_types: ["code"],
				// `reports` is outside the ceiling of `registration.scope`.
				scope: "profile",
				client_name: "App",
				"client_name#fr-CA": "Appli",
			},
		);
		const stored = await env.idp.oauth2.clients.getClient(answer.client_id);
		ok(stored && (await env.idp.oauth2.clients.verifySecret(stored, answer.client_secret ?? "")));
		deepEqual([stored.registered_by, stored.localized], ["dynamic", { "client_name#fr-CA": "Appli" }]);
		deepEqual(
			registered.map((client) => client.client_id),
			[answer.client_id],
		);
	});
	it("should answer no secret fields for a public client", async () => {
		const answer = await env.idp.oauth2.registerClient({ ...web, token_endpoint_auth_method: "none" });
		ok(!("client_secret" in answer) && !("client_secret_expires_at" in answer));
	});
	it("should never let a dynamic client set the fields only the server sets", async () => {
		const answer = await env.idp.oauth2.registerClient({
			...web,
			skip_consent: true,
			introspect: true,
			audience: "https://api.example.com",
		});
		const stored = await env.idp.oauth2.clients.getClient(answer.client_id);
		deepEqual([stored?.skip_consent, stored?.introspect, stored?.audience], [undefined, undefined, undefined]);
	});
	it("should let an admin set them, with every scope as the ceiling", async () => {
		const answer = await env.idp.oauth2.registerClient(
			{ ...web, skip_consent: true, scope: "profile reports" },
			{ registered_by: "admin" },
		);
		const stored = await env.idp.oauth2.clients.getClient(answer.client_id);
		deepEqual([stored?.skip_consent, stored?.registered_by, stored?.scope], [true, "admin", "profile reports"]);
	});
	it("should give a dynamic secret the lifetime of the registration", async () => {
		setup({ registration: { secret_lifetime: 3600 } });
		const answer = await env.idp.oauth2.registerClient(web);
		ok(Math.abs((answer.client_secret_expires_at ?? 0) - (Date.now() / 1000 + 3600)) < 5);
	});
	it("should run the policy, check its result, and strip the fields only the server sets", async () => {
		setup({
			registration: {
				policy: (metadata) => {
					if (metadata.client_name?.includes("Bank")) {
						throw new InvalidClientMetadataError("client_name is not allowed");
					}
					return { ...metadata, client_name: `${metadata.client_name} (third party)`, skip_consent: true };
				},
			},
		});
		const answer = await env.idp.oauth2.registerClient(web);
		deepEqual(answer.client_name, "App (third party)");
		deepEqual((await env.idp.oauth2.clients.getClient(answer.client_id))?.skip_consent, undefined);
		await rejects(() => env.idp.oauth2.registerClient({ ...web, client_name: "Bank" }), InvalidClientMetadataError);
		setup({ registration: { policy: (metadata) => ({ ...metadata, redirect_uris: [] }) } });
		await rejects(() => env.idp.oauth2.registerClient(web), InvalidClientMetadataError);
		deepEqual(registered, []);
	});
	it("should announce the endpoint in the metadata only when registration is open", () => {
		deepEqual(env.idp.oauth2.metadata("http://localhost").registration_endpoint, "http://localhost/register");
		setup({ registration: false });
		deepEqual(env.idp.oauth2.metadata("http://localhost").registration_endpoint, undefined);
	});
});
