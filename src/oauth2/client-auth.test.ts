import { deepEqual, ok, rejects, throws } from "node:assert";
import { beforeEach, describe, it } from "vitest";
import { createAuthDanceMemoryOauth2ClientStorage } from "../providers/memory.ts";
import { authenticateClient, readClientCredentials } from "./client-auth.ts";
import { InvalidClientError, InvalidRequestError } from "./error.ts";
import type { AuthDanceOauth2ClientStorage } from "./storage.ts";

function basic(id: string, secret: string): string {
	return `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`;
}

describe("readClientCredentials", () => {
	it("should read Basic credentials, form-decoded after base64", () => {
		deepEqual(readClientCredentials(basic("cli_a", "s:e c+r%t"), new Map()), {
			client_id: "cli_a",
			client_secret: "s:e c+r%t",
			method: "client_secret_basic",
		});
		// RFC 6749 Appendix B: `+` is a space.
		deepEqual(readClientCredentials(`Basic ${btoa("cli_a:a+b")}`, new Map()).client_secret, "a b");
	});
	it("should read client_secret_post and none from the body", () => {
		deepEqual(
			readClientCredentials(
				undefined,
				new Map([
					["client_id", "cli_a"],
					["client_secret", "s"],
				]),
			),
			{
				client_id: "cli_a",
				client_secret: "s",
				method: "client_secret_post",
			},
		);
		deepEqual(readClientCredentials(undefined, new Map([["client_id", "cli_a"]])), { client_id: "cli_a", method: "none" });
		// A header with another scheme counts as absent.
		deepEqual(readClientCredentials("Bearer x", new Map([["client_id", "cli_a"]])).method, "none");
	});
	it("should refuse two methods at once, and two client ids", () => {
		throws(() => readClientCredentials(basic("cli_a", "s"), new Map([["client_secret", "s"]])), InvalidRequestError);
		throws(() => readClientCredentials(basic("cli_a", "s"), new Map([["client_id", "cli_b"]])), InvalidRequestError);
		readClientCredentials(basic("cli_a", "s"), new Map([["client_id", "cli_a"]]));
	});
	it("should refuse malformed Basic credentials and a request with no client", () => {
		for (const header of ["Basic !!!", `Basic ${btoa("no-colon")}`, `Basic ${btoa(":secret")}`, `Basic ${btoa("cli_a:%E0%A4%A")}`]) {
			throws(() => readClientCredentials(header, new Map()), InvalidClientError, header);
		}
		throws(() => readClientCredentials(undefined, new Map()), InvalidClientError);
	});
});

describe("authenticateClient", () => {
	let clients: AuthDanceOauth2ClientStorage;
	let secret: string;

	beforeEach(async () => {
		clients = createAuthDanceMemoryOauth2ClientStorage();
		const created = await clients.createClient({ scope: "profile" });
		ok(created.client_secret);
		secret = created.client_secret;
		await clients.updateClient({ ...created.client, client_id: "cli_basic" });
		await clients.updateClient({ ...created.client, client_id: "cli_post", token_endpoint_auth_method: "client_secret_post" });
		await clients
			.createClient({ scope: "profile", token_endpoint_auth_method: "none", redirect_uris: ["https://a.example.com/cb"] })
			.then(({ client }) => clients.updateClient({ ...client, client_id: "cli_public" }));
	});

	it("should authenticate each method", async () => {
		deepEqual(
			(await authenticateClient(clients, { client_id: "cli_basic", client_secret: secret, method: "client_secret_basic" })).client_id,
			"cli_basic",
		);
		deepEqual(
			(await authenticateClient(clients, { client_id: "cli_post", client_secret: secret, method: "client_secret_post" })).client_id,
			"cli_post",
		);
		deepEqual((await authenticateClient(clients, { client_id: "cli_public", method: "none" })).client_id, "cli_public");
	});
	it("should refuse an unknown client, another method, and a wrong secret", async () => {
		await rejects(() => authenticateClient(clients, { client_id: "cli_missing", method: "none" }), InvalidClientError);
		await rejects(
			() => authenticateClient(clients, { client_id: "cli_basic", client_secret: secret, method: "client_secret_post" }),
			InvalidClientError,
		);
		await rejects(() => authenticateClient(clients, { client_id: "cli_basic", method: "none" }), InvalidClientError);
		await rejects(
			() => authenticateClient(clients, { client_id: "cli_public", client_secret: "x", method: "client_secret_post" }),
			InvalidClientError,
		);
		await rejects(
			() => authenticateClient(clients, { client_id: "cli_basic", client_secret: "wrong", method: "client_secret_basic" }),
			InvalidClientError,
		);
	});
});
