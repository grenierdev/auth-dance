import { throws as assertThrows, deepEqual, ok, rejects } from "node:assert";
import { encode as encodeBase64Url } from "jose/base64url";
import { describe, it, assert as vitestAssert } from "vitest";
import type { AuthDanceComponentContext } from "../component.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentityComponent, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";
import { MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "../providers/memory.ts";
import { AuthDanceStorage } from "../storage.ts";
import { WebAuthnAuthDanceComponent } from "./webauthn.ts";

const RP = { id: "example.com", name: "Example" };
const ORIGIN = "https://example.com";
const FLAGS_REGISTER = 0x01 | 0x04 | 0x40;
const FLAGS_AUTHENTICATE = 0x01 | 0x04;

function storage(): AuthDanceStorage {
	return new AuthDanceStorage({
		identity: new MemoryIdentityProvider(),
		kv: new MemoryKvProvider(),
		rate_limiter: new MemoryRateLimiterProvider(),
	});
}

/** One step of a dance. Without `components` the context carries no identity, the way a sign-in does. */
function context(
	store: AuthDanceStorage,
	options: {
		flow?: string;
		components?: AuthDanceIdentityComponent[];
		id?: string;
		name?: string;
	} = {},
): AuthDanceComponentContext {
	return {
		storage: store,
		stateId: "st_test",
		name: options.name ?? "webauthn",
		flow: options.flow ?? "sign-in",
		identity: options.components && { id: options.id ?? "id_test", data: {}, components: options.components },
	};
}

function publicKey(prompt: AuthDancePromptInput): Record<string, unknown> {
	return prompt.options?.publicKey as Record<string, unknown>;
}

function challengeOf(prompt: AuthDancePromptInput): string {
	return publicKey(prompt).challenge as string;
}

/** Writes one ASN.1 DER INTEGER, without its leading zero bytes and with a zero when the first byte reads as a sign. */
function derInteger(bytes: Uint8Array): number[] {
	let start = 0;
	while (start < bytes.length - 1 && bytes[start] === 0) {
		start++;
	}
	const value = Array.from(bytes.subarray(start));
	if ((value[0] & 0x80) !== 0) {
		value.unshift(0);
	}
	return [0x02, value.length, ...value];
}

/** Wraps the two halves an ECDSA signature of `crypto.subtle` gives into the DER form that WebAuthn asks for. */
function derEcdsaSignature(raw: Uint8Array): Uint8Array {
	const half = raw.length / 2;
	const body = [...derInteger(raw.subarray(0, half)), ...derInteger(raw.subarray(half))];
	const header = body.length < 128 ? [0x30, body.length] : [0x30, 0x81, body.length];
	return new Uint8Array([...header, ...body]);
}

async function digest(data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

/** Builds the authenticator data. With a credential id the method adds the attested credential data of a registration. */
async function authenticatorData(options: {
	rpId?: string;
	flags: number;
	signCount?: number;
	credentialId?: Uint8Array;
}): Promise<Uint8Array> {
	const head = new Uint8Array(37);
	head.set(await digest(new TextEncoder().encode(options.rpId ?? RP.id)));
	head[32] = options.flags;
	new DataView(head.buffer).setUint32(33, options.signCount ?? 0);
	if (!options.credentialId) {
		return head;
	}
	// The aaguid, the length of the credential id, the credential id, then the COSE key the component never reads.
	const tail = new Uint8Array(16 + 2 + options.credentialId.length + 8);
	tail.set(new Uint8Array(16).fill(0x11));
	new DataView(tail.buffer).setUint16(16, options.credentialId.length);
	tail.set(options.credentialId, 18);
	tail.set(new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21]), 18 + options.credentialId.length);
	const data = new Uint8Array(head.length + tail.length);
	data.set(head);
	data.set(tail, head.length);
	return data;
}

interface FakeAuthenticator {
	/** The credential id in base64url, which is also the identification of the record. */
	id: string;
	/** The COSE identifier of the algorithm the authenticator signs with. */
	algorithm: number;
	/** Answers a prompt of the type `webauthn-create`. */
	register(prompt: AuthDancePromptInput, overrides?: Record<string, unknown>): Promise<Record<string, unknown>>;
	/** Answers a prompt of the type `webauthn`. */
	authenticate(
		prompt: AuthDancePromptInput,
		overrides?: {
			origin?: string;
			flags?: number;
			signCount?: number;
			rpId?: string;
			type?: string;
			challenge?: string;
			userHandle?: string;
		},
	): Promise<Record<string, unknown>>;
}

/** An authenticator that holds one credential and signs the way the specification asks for. */
async function fakeAuthenticator(options: { algorithm?: number } = {}): Promise<FakeAuthenticator> {
	const algorithm = options.algorithm ?? -7;
	const curve = algorithm === -7 ? "P-256" : "P-521";
	const parameters: EcKeyGenParams | RsaHashedKeyGenParams =
		algorithm === -257
			? { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }
			: { name: "ECDSA", namedCurve: curve };
	const keys = (await crypto.subtle.generateKey(parameters, true, ["sign", "verify"])) as CryptoKeyPair;
	const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey));
	const credentialId = crypto.getRandomValues(new Uint8Array(32));
	const id = encodeBase64Url(credentialId);

	function clientData(type: string, challenge: string, origin: string): Uint8Array {
		return new TextEncoder().encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
	}

	async function sign(data: Uint8Array, client: Uint8Array): Promise<Uint8Array> {
		const hash = await digest(client);
		const signed = new Uint8Array(data.length + hash.length);
		signed.set(data);
		signed.set(hash, data.length);
		if (algorithm === -257) {
			return new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, signed as BufferSource));
		}
		const hashName = algorithm === -7 ? "SHA-256" : "SHA-512";
		return derEcdsaSignature(
			new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: hashName }, keys.privateKey, signed as BufferSource)),
		);
	}

	return {
		id,
		algorithm,
		async register(prompt, overrides = {}) {
			const client = clientData("webauthn.create", challengeOf(prompt), ORIGIN);
			const data = await authenticatorData({ flags: FLAGS_REGISTER, credentialId });
			return {
				id,
				rawId: id,
				type: "public-key",
				clientExtensionResults: {},
				response: {
					clientDataJSON: encodeBase64Url(client),
					authenticatorData: encodeBase64Url(data),
					attestationObject: encodeBase64Url(new Uint8Array([0xa0])),
					transports: ["internal", "hybrid"],
					publicKey: encodeBase64Url(spki),
					publicKeyAlgorithm: algorithm,
					...overrides,
				},
			};
		},
		async authenticate(prompt, overrides = {}) {
			const client = clientData(overrides.type ?? "webauthn.get", overrides.challenge ?? challengeOf(prompt), overrides.origin ?? ORIGIN);
			const data = await authenticatorData({
				rpId: overrides.rpId,
				flags: overrides.flags ?? FLAGS_AUTHENTICATE,
				signCount: overrides.signCount ?? 0,
			});
			return {
				id,
				rawId: id,
				type: "public-key",
				clientExtensionResults: {},
				response: {
					clientDataJSON: encodeBase64Url(client),
					authenticatorData: encodeBase64Url(data),
					signature: encodeBase64Url(await sign(data, client)),
					...(overrides.userHandle ? { userHandle: overrides.userHandle } : {}),
				},
			};
		},
	};
}

/** Runs a whole registration and gives back the record it produced. */
async function enroll(
	component: WebAuthnAuthDanceComponent,
	store: AuthDanceStorage,
	options: {
		flow?: string;
		authenticator?: FakeAuthenticator;
		confirmed?: boolean;
		components?: AuthDanceIdentityComponent[];
		id?: string;
	} = {},
): Promise<{ authenticator: FakeAuthenticator; record: AuthDanceIdentityIdentification }> {
	const flow = options.flow ?? "enroll";
	const authenticator = options.authenticator ?? (await fakeAuthenticator());
	const collecting = context(store, { flow, components: options.components ?? [], id: options.id });
	const prompt = await component.getPrompt(collecting);
	const value = await authenticator.register(prompt);
	const [record] = await component.getIdentityComponent("webauthn", value, options.confirmed ?? false, collecting);
	return { authenticator, record: record as AuthDanceIdentityIdentification };
}

describe("WebAuthnAuthDanceComponent", () => {
	it("should refuse an algorithm it cannot verify", () => {
		assertThrows(() => new WebAuthnAuthDanceComponent({ rp: RP, algorithms: [-7, -65535] }), Error);
	});

	it("should ask the client to make a credential, and to sign with one", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		// Every flow that collects a credential.
		for (const flow of ["sign-up", "enroll", "rotate"]) {
			const prompt = await component.getPrompt(context(store, { flow, components: [] }));
			deepEqual(prompt.type, "webauthn-create");
			deepEqual(publicKey(prompt).rp, RP);
			deepEqual(publicKey(prompt).pubKeyCredParams, [
				{ type: "public-key", alg: -7 },
				{ type: "public-key", alg: -257 },
			]);
			deepEqual(prompt.sendable, false);
		}
		// A sign-up builds its prompt before the library holds an identity.
		const signUp = await component.getPrompt(context(store, { flow: "sign-up" }));
		deepEqual(signUp.type, "webauthn-create");
		// A sign-in signs, and it names no credential, so only a credential the authenticator keeps answers.
		const signIn = await component.getPrompt(context(store, { flow: "sign-in" }));
		deepEqual(signIn.type, "webauthn");
		deepEqual(publicKey(signIn).allowCredentials, []);
		deepEqual(publicKey(signIn).rpId, RP.id);
		// A recovery proves an enrolled credential first, then it collects the replacement.
		deepEqual((await component.getPrompt(context(store, { flow: "recover" }))).type, "webauthn");
		deepEqual((await component.getPrompt(context(store, { flow: "recover", components: [] }))).type, "webauthn-create");
		// The verification of a collected credential always signs.
		const verification = await component.verificationComponent(context(store, { flow: "enroll", components: [] }));
		deepEqual((await verification.getPrompt(context(store, { flow: "enroll", components: [] }))).type, "webauthn");
	});

	it("should store the credential the client registered", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const { authenticator, record } = await enroll(component, store);
		deepEqual(record.kind, "identification");
		deepEqual(record.component, "webauthn");
		deepEqual(record.identification, authenticator.id);
		deepEqual(record.confirmed, false);
		deepEqual(record.data?.algorithm, -7);
		deepEqual(record.data?.aaguid, "11".repeat(16));
		deepEqual(record.data?.transports, ["internal", "hybrid"]);
		deepEqual(record.data?.signCount, 0);
		deepEqual(record.data?.uvInitialized, true);
		deepEqual(typeof record.data?.publicKey, "string");
		// The handle of an identity that the library already holds is the id of that identity.
		deepEqual(record.data?.userHandle, encodeBase64Url(new TextEncoder().encode("id_test")));
	});

	it("should name the enrolled credentials the client must not repeat", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const { authenticator, record } = await enroll(component, store);
		const prompt = await component.getPrompt(context(store, { flow: "rotate", components: [{ ...record, confirmed: true }] }));
		deepEqual(publicKey(prompt).excludeCredentials, [
			{
				type: "public-key",
				id: authenticator.id,
				transports: ["internal", "hybrid"],
			},
		]);
	});

	it("should refuse a registration that answers no prompt", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const authenticator = await fakeAuthenticator();
		// A prompt of a state, and a registration submitted under another one.
		const prompt = await component.getPrompt(context(store, { flow: "enroll", components: [] }));
		const value = await authenticator.register(prompt);
		const other = { ...context(store, { flow: "enroll", components: [] }), stateId: "st_other" };
		await rejects(() => component.getIdentityComponent("webauthn", value, false, other), InvalidPromptValueError);
	});

	it("should refuse a registration that does not read", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const ctx = context(store, { flow: "enroll", components: [] });
		await component.getPrompt(ctx);
		for (const value of ["", 42, null, undefined, {}, { type: "public-key" }, { id: "a", type: "public-key", response: {} }]) {
			await rejects(() => component.getIdentityComponent("webauthn", value, false, ctx), InvalidPromptValueError);
		}
	});

	it("should refuse a registration whose client data fails a check", async () => {
		const store = storage();
		const authenticator = await fakeAuthenticator();
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const ctx = context(store, { flow: "enroll", components: [] });
		const prompt = await component.getPrompt(ctx);
		const client = (fields: Record<string, unknown>) =>
			encodeBase64Url(
				new TextEncoder().encode(
					JSON.stringify({
						type: "webauthn.create",
						challenge: challengeOf(prompt),
						origin: ORIGIN,
						crossOrigin: false,
						...fields,
					}),
				),
			);
		for (const fields of [{ challenge: "AAAA" }, { origin: "https://phish.example" }, { crossOrigin: true }, { type: "webauthn.get" }]) {
			const value = await authenticator.register(prompt, { clientDataJSON: client(fields) });
			await rejects(() => component.getIdentityComponent("webauthn", value, false, ctx), InvalidPromptValueError);
		}
	});

	it("should refuse a registration whose authenticator data fails a check", async () => {
		const store = storage();
		const authenticator = await fakeAuthenticator();
		const component = new WebAuthnAuthDanceComponent({ rp: RP, userVerification: "required" });
		const ctx = context(store, { flow: "enroll", components: [] });
		const prompt = await component.getPrompt(ctx);
		const credentialId = crypto.getRandomValues(new Uint8Array(32));
		for (const data of [
			// Another relying party.
			await authenticatorData({ rpId: "phish.example", flags: FLAGS_REGISTER, credentialId }),
			// The owner was not present, and the owner did not verify themself.
			await authenticatorData({ flags: 0x40, credentialId }),
			await authenticatorData({ flags: 0x01 | 0x40, credentialId }),
			// A credential that cannot leave its authenticator, and that rests somewhere else.
			await authenticatorData({ flags: FLAGS_REGISTER | 0x10, credentialId }),
			// No attested credential data at all.
			await authenticatorData({ flags: 0x01 | 0x04 }),
		]) {
			const value = await authenticator.register(prompt, { authenticatorData: encodeBase64Url(data) });
			await rejects(() => component.getIdentityComponent("webauthn", value, false, ctx), InvalidPromptValueError);
		}
	});

	it("should refuse a registration whose credential id answers to another key", async () => {
		const store = storage();
		const authenticator = await fakeAuthenticator();
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const ctx = context(store, { flow: "enroll", components: [] });
		const prompt = await component.getPrompt(ctx);
		// The attested credential data names a credential id, and the client reports another one.
		const data = await authenticatorData({ flags: FLAGS_REGISTER, credentialId: crypto.getRandomValues(new Uint8Array(32)) });
		const value = await authenticator.register(prompt, { authenticatorData: encodeBase64Url(data) });
		await rejects(() => component.getIdentityComponent("webauthn", value, false, ctx), InvalidPromptValueError);
	});

	it("should refuse an algorithm it did not ask for, and a public key that does not read", async () => {
		const store = storage();
		const authenticator = await fakeAuthenticator();
		const component = new WebAuthnAuthDanceComponent({ rp: RP, algorithms: [-7] });
		const ctx = context(store, { flow: "enroll", components: [] });
		const prompt = await component.getPrompt(ctx);
		const wrongAlgorithm = await authenticator.register(prompt, { publicKeyAlgorithm: -257 });
		await rejects(() => component.getIdentityComponent("webauthn", wrongAlgorithm, false, ctx), InvalidPromptValueError);
		// A user agent that understands no such algorithm reports no public key at all.
		const noKey = await authenticator.register(prompt, { publicKey: undefined });
		await rejects(() => component.getIdentityComponent("webauthn", noKey, false, ctx), InvalidPromptValueError);
		const junkKey = await authenticator.register(prompt, { publicKey: encodeBase64Url(new Uint8Array([1, 2, 3])) });
		await rejects(() => component.getIdentityComponent("webauthn", junkKey, false, ctx), InvalidPromptValueError);
	});

	it("should refuse a credential id that already belongs to an identity", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const { authenticator, record } = await enroll(component, store);
		await store.createIdentity({}, [{ ...record, confirmed: true }]);
		const ctx = context(store, { flow: "enroll", components: [] });
		const prompt = await component.getPrompt(ctx);
		const value = await authenticator.register(prompt);
		await rejects(() => component.getIdentityComponent("webauthn", value, false, ctx), InvalidPromptValueError);
	});

	it("should resolve the owner of the credential that signed", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const { authenticator, record } = await enroll(component, store);
		const identity = await store.createIdentity({}, [{ ...record, confirmed: true }]);
		// A sign-in carries no identity. The credential id names the owner.
		const ctx = context(store, { flow: "sign-in" });
		const prompt = await component.getPrompt(ctx);
		deepEqual(await component.verifyPrompt(await authenticator.authenticate(prompt), ctx), identity.id);
	});

	it("should verify a signature that carries no ASN.1 wrapper", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP, algorithms: [-257] });
		const store = storage();
		const authenticator = await fakeAuthenticator({ algorithm: -257 });
		const { record } = await enroll(component, store, { authenticator });
		const identity = await store.createIdentity({}, [{ ...record, confirmed: true }]);
		const ctx = context(store, { flow: "sign-in" });
		const prompt = await component.getPrompt(ctx);
		deepEqual(await component.verifyPrompt(await authenticator.authenticate(prompt), ctx), identity.id);
	});

	it("should verify a signature whose ASN.1 wrapper carries a long length", async () => {
		// One integer of a P-521 signature reaches 66 bytes, so the sequence writes its length over two bytes.
		const component = new WebAuthnAuthDanceComponent({ rp: RP, algorithms: [-36] });
		const store = storage();
		const authenticator = await fakeAuthenticator({ algorithm: -36 });
		const { record } = await enroll(component, store, { authenticator });
		const identity = await store.createIdentity({}, [{ ...record, confirmed: true }]);
		const ctx = context(store, { flow: "sign-in" });
		const prompt = await component.getPrompt(ctx);
		deepEqual(await component.verifyPrompt(await authenticator.authenticate(prompt), ctx), identity.id);
	});

	it("should refuse a signature that answers no prompt of its own", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const { authenticator, record } = await enroll(component, store);
		await store.createIdentity({}, [{ ...record, confirmed: true }]);
		const ctx = context(store, { flow: "sign-in" });
		const prompt = await component.getPrompt(ctx);
		const value = await authenticator.authenticate(prompt);
		// The answer works one time. The method drops the challenge, so the same answer no longer reads.
		ok(await component.verifyPrompt(value, ctx));
		vitestAssert.isFalse(await component.verifyPrompt(value, ctx));
		// A fresh prompt carries a fresh challenge, which the old answer does not carry.
		await component.getPrompt(ctx);
		vitestAssert.isFalse(await component.verifyPrompt(value, ctx));
	});

	it("should refuse a signature that does not check out", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP, userVerification: "required" });
		const store = storage();
		const { authenticator, record } = await enroll(component, store);
		await store.createIdentity({}, [{ ...record, confirmed: true }]);
		const ctx = context(store, { flow: "sign-in" });
		for (const overrides of [
			{ origin: "https://phish.example" },
			{ rpId: "phish.example" },
			{ type: "webauthn.create" },
			{ challenge: "AAAA" },
			{ flags: 0x00 },
			{ flags: 0x01 },
			{ userHandle: encodeBase64Url(new TextEncoder().encode("id_other")) },
		]) {
			const prompt = await component.getPrompt(ctx);
			vitestAssert.isFalse(await component.verifyPrompt(await authenticator.authenticate(prompt, overrides), ctx));
		}
		// A signature of another key over the right data.
		const prompt = await component.getPrompt(ctx);
		const other = await fakeAuthenticator();
		const forged = await other.authenticate(prompt);
		vitestAssert.isFalse(await component.verifyPrompt({ ...forged, id: authenticator.id, rawId: authenticator.id }, ctx));
	});

	it("should refuse a signature that does not read, and a credential nobody holds", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const authenticator = await fakeAuthenticator();
		const ctx = context(store, { flow: "sign-in" });
		const prompt = await component.getPrompt(ctx);
		for (const value of ["", 42, null, undefined, {}, { id: "a", type: "public-key", response: {} }]) {
			vitestAssert.isFalse(await component.verifyPrompt(value, ctx));
		}
		// The signature reads, and no identity holds that credential.
		vitestAssert.isFalse(await component.verifyPrompt(await authenticator.authenticate(prompt), ctx));
	});

	it("should refuse a credential that nobody confirmed", async () => {
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const store = storage();
		const { authenticator, record } = await enroll(component, store);
		await store.createIdentity({}, [record]);
		const ctx = context(store, { flow: "sign-in" });
		const prompt = await component.getPrompt(ctx);
		vitestAssert.isFalse(await component.verifyPrompt(await authenticator.authenticate(prompt), ctx));
	});

	it("should read the signature counter as a signal of a copy", async () => {
		const store = storage();
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const { authenticator, record } = await enroll(component, store);
		const identity = await store.createIdentity({}, [{ ...record, confirmed: true }]);
		const ctx = context(store, { flow: "sign-in" });
		// The counter goes up, then it stands still.
		deepEqual(
			await component.verifyPrompt(await authenticator.authenticate(await component.getPrompt(ctx), { signCount: 7 }), ctx),
			identity.id,
		);
		vitestAssert.isFalse(
			await component.verifyPrompt(await authenticator.authenticate(await component.getPrompt(ctx), { signCount: 7 }), ctx),
		);
		deepEqual(
			await component.verifyPrompt(await authenticator.authenticate(await component.getPrompt(ctx), { signCount: 8 }), ctx),
			identity.id,
		);
		// An owner that turns the check off keeps the credential usable.
		const lenient = new WebAuthnAuthDanceComponent({ rp: RP, cloneDetection: false });
		deepEqual(
			await lenient.verifyPrompt(await authenticator.authenticate(await lenient.getPrompt(ctx), { signCount: 8 }), ctx),
			identity.id,
		);
	});

	it("should confirm the credential the flow just collected, and no other", async () => {
		const store = storage();
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const enrolled = await enroll(component, store, { confirmed: true });
		// A rotation collects the replacement in front of the credential it replaces.
		const collected = await enroll(component, store, {
			flow: "rotate",
			components: [{ ...enrolled.record, confirmed: true }],
		});
		const ctx = context(store, {
			flow: "rotate",
			components: [collected.record, { ...enrolled.record, confirmed: true }],
		});
		const verification = await component.verificationComponent(ctx);
		const prompt = await verification.getPrompt(ctx);
		// The prompt names the new credential, and only that one.
		deepEqual(
			(publicKey(prompt).allowCredentials as Array<Record<string, unknown>>).map((c) => c.id),
			[collected.authenticator.id],
		);
		// The credential it replaces cannot confirm the replacement.
		vitestAssert.isFalse(await verification.verifyPrompt(await enrolled.authenticator.authenticate(prompt), ctx));
		const fresh = await verification.getPrompt(ctx);
		deepEqual(await verification.verifyPrompt(await collected.authenticator.authenticate(fresh), ctx), true);
	});

	it("should prove an enrolled credential when the flow collected none", async () => {
		const store = storage();
		const component = new WebAuthnAuthDanceComponent({ rp: RP });
		const { authenticator, record } = await enroll(component, store, { confirmed: true });
		// The first step of a rotation, and of a recovery: the identity holds the credential, and nothing is collected.
		const ctx = context(store, { flow: "rotate", components: [{ ...record, confirmed: true }] });
		const verification = await component.verificationComponent(ctx);
		const prompt = await verification.getPrompt(ctx);
		deepEqual(
			(publicKey(prompt).allowCredentials as Array<Record<string, unknown>>).map((c) => c.id),
			[authenticator.id],
		);
		// A verification answers `true`, and never an identity id.
		deepEqual(await verification.verifyPrompt(await authenticator.authenticate(prompt), ctx), true);
	});
});
