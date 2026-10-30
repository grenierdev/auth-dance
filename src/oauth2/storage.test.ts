import { deepEqual, ok, rejects } from "node:assert";
import { beforeEach, describe, it } from "vitest";
import { testOauth2Client } from "../fixtures.test.ts";
import { MemoryOauth2ClientProvider } from "../providers/memory.ts";
import type { AuthDanceOauth2GrantType } from "./client.ts";
import { InvalidClientError, InvalidClientMetadataError, InvalidRedirectUriError } from "./error.ts";
import { sha256 } from "./records.ts";
import { AuthDanceOauth2ClientStorage, hashClientSecret } from "./storage.ts";

describe("AuthDanceOauth2ClientStorage", () => {
	let provider: MemoryOauth2ClientProvider;
	let storage: AuthDanceOauth2ClientStorage;

	beforeEach(() => {
		provider = new MemoryOauth2ClientProvider();
		storage = new AuthDanceOauth2ClientStorage({ clients: provider });
	});

	it("should create a confidential client, and keep only the hash of its secret", async () => {
		const { client, client_secret } = await storage.createClient({ redirect_uris: ["https://app.example.com/callback"], scope: "profile" });
		ok(client.client_id.startsWith("cli_"));
		ok(client_secret && client_secret.length === 43);
		deepEqual(client.client_secret_hash, await sha256(client_secret));
		deepEqual(await provider.get(client.client_id), client);
		ok(!JSON.stringify(await provider.get(client.client_id)).includes(client_secret));
	});
	it("should fill the defaults of RFC 7591", async () => {
		const { client } = await storage.createClient({ redirect_uris: ["https://app.example.com/callback"], scope: "profile" });
		deepEqual(
			[client.token_endpoint_auth_method, client.grant_types, client.response_types, client.client_secret_expires_at, client.registered_by],
			["client_secret_basic", ["authorization_code"], ["code"], 0, "admin"],
		);
		ok(Math.abs(client.client_id_issued_at - Date.now() / 1000) < 5);
		const { client: machine } = await storage.createClient({ grant_types: ["client_credentials"], scope: "reports" });
		deepEqual([machine.redirect_uris, machine.response_types], [[], []]);
	});
	it("should create a public client with no secret", async () => {
		const result = await storage.createClient({
			redirect_uris: ["com.example.app:/callback"],
			token_endpoint_auth_method: "none",
			scope: "profile",
		});
		deepEqual(result.client_secret, undefined);
		ok(!("client_secret_hash" in result.client));
		ok(!(await storage.verifySecret(result.client, "")));
	});
	it("should refuse a redirect URI or a field that does not pass", async () => {
		await rejects(
			() => storage.createClient({ redirect_uris: ["http://app.example.com/callback"], scope: "profile" }),
			InvalidRedirectUriError,
		);
		await rejects(
			() => storage.createClient({ grant_types: ["password" as AuthDanceOauth2GrantType], scope: "profile" }),
			(error) => error instanceof InvalidClientMetadataError && error.description === "grant_types.0 is not valid",
		);
		deepEqual(await provider.list(), []);
	});
	it("should verify a secret", async () => {
		const { client, client_secret } = await storage.createClient({ scope: "profile" });
		ok(client_secret);
		ok(await storage.verifySecret(client, client_secret));
		ok(!(await storage.verifySecret(client, `${client_secret.slice(0, -1)}${client_secret.endsWith("A") ? "B" : "A"}`)));
		ok(!(await storage.verifySecret(client, "")));
		ok(await storage.verifySecret({ ...client, client_secret_expires_at: Math.floor(Date.now() / 1000) + 60 }, client_secret));
		ok(!(await storage.verifySecret({ ...client, client_secret_expires_at: Math.floor(Date.now() / 1000) - 1 }, client_secret)));
	});
	it("should rotate a secret, and stop the old one", async () => {
		const { client, client_secret } = await storage.createClient({ scope: "profile" });
		ok(client_secret);
		const rotated = await storage.rotateSecret(client.client_id);
		const stored = await storage.getClient(client.client_id);
		ok(stored);
		ok(await storage.verifySecret(stored, rotated));
		ok(!(await storage.verifySecret(stored, client_secret)));
	});
	it("should refuse to rotate the secret of an unknown or a public client", async () => {
		const { client } = await storage.createClient({
			token_endpoint_auth_method: "none",
			redirect_uris: ["https://a.example.com/cb"],
			scope: "profile",
		});
		await rejects(() => storage.rotateSecret(client.client_id), InvalidClientError);
		await rejects(() => storage.rotateSecret("cli_missing"), InvalidClientError);
	});
	it("should check a client before an update", async () => {
		const { client } = await storage.createClient({ redirect_uris: ["https://app.example.com/callback"], scope: "profile" });
		await rejects(() => storage.updateClient({ ...client, redirect_uris: ["javascript:alert(1)"] }), InvalidRedirectUriError);
		await storage.updateClient({ ...client, scope: "profile email" });
		deepEqual((await storage.getClient(client.client_id))?.scope, "profile email");
	});
	it("should verify the secret of a client seeded with hashClientSecret", async () => {
		const seeded = new AuthDanceOauth2ClientStorage({
			clients: new MemoryOauth2ClientProvider([testOauth2Client({ client_secret_hash: await hashClientSecret("s3cret") })]),
		});
		const client = await seeded.getClient("cli_test");
		ok(client);
		ok(await seeded.verifySecret(client, "s3cret"));
	});
	it("should list and delete clients", async () => {
		const { client: a } = await storage.createClient({ scope: "profile" });
		const { client: b } = await storage.createClient({ scope: "profile" });
		deepEqual(
			(await storage.listClients()).map((client) => client.client_id),
			[a.client_id, b.client_id].sort(),
		);
		await storage.deleteClient(a.client_id);
		deepEqual(await storage.getClient(a.client_id), undefined);
	});
});
