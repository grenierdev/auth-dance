import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";
import { encodeHex } from "@std/encoding/hex";
import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent, AuthDanceIdentityIdentification } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/** The bits of the `flags` byte of the authenticator data, WebAuthn level 3 section 6.1. */
const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_BACKUP_ELIGIBLE = 0x08;
const FLAG_BACKUP_STATE = 0x10;
const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

/** The largest credential id an authenticator may report, WebAuthn level 3 section 6.5.1. */
const CREDENTIAL_ID_LIMIT = 1023;

/** What one entry of the algorithm table gives `crypto.subtle`. */
interface WebAuthnAlgorithm {
	/** What `importKey` reads the stored key with. */
	key: Parameters<SubtleCrypto["importKey"]>[2];
	/** What `verify` checks the signature with. */
	verify: Parameters<SubtleCrypto["verify"]>[0];
	/**
	 * The length in bytes of one half of an ECDSA signature. A value above zero also marks the signature as an
	 * ASN.1 DER `Ecdsa-Sig-Value`, which `crypto.subtle` does not read.
	 */
	coordinate: number;
}

/**
 * The COSE algorithms the component verifies, from the IANA COSE Algorithms registry. `-7` and `-257` cover almost
 * every authenticator in service.
 *
 * An ECDSA signature carries an ASN.1 DER wrapper, and every other signature here is raw, WebAuthn level 3
 * section 6.5.5.
 */
const ALGORITHMS: Record<number, WebAuthnAlgorithm> = {
	// ES256, ES384, ES512.
	[-7]: { key: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" }, coordinate: 32 },
	[-35]: { key: { name: "ECDSA", namedCurve: "P-384" }, verify: { name: "ECDSA", hash: "SHA-384" }, coordinate: 48 },
	[-36]: { key: { name: "ECDSA", namedCurve: "P-521" }, verify: { name: "ECDSA", hash: "SHA-512" }, coordinate: 66 },
	// EdDSA over Ed25519.
	[-8]: { key: { name: "Ed25519" }, verify: { name: "Ed25519" }, coordinate: 0 },
	// RS256, RS384, RS512.
	[-257]: { key: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" }, coordinate: 0 },
	[-258]: { key: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" }, verify: { name: "RSASSA-PKCS1-v1_5" }, coordinate: 0 },
	[-259]: { key: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" }, verify: { name: "RSASSA-PKCS1-v1_5" }, coordinate: 0 },
	// PS256, PS384, PS512.
	[-37]: { key: { name: "RSA-PSS", hash: "SHA-256" }, verify: { name: "RSA-PSS", saltLength: 32 }, coordinate: 0 },
	[-38]: { key: { name: "RSA-PSS", hash: "SHA-384" }, verify: { name: "RSA-PSS", saltLength: 48 }, coordinate: 0 },
	[-39]: { key: { name: "RSA-PSS", hash: "SHA-512" }, verify: { name: "RSA-PSS", saltLength: 64 }, coordinate: 0 },
};

/** Reads a value as a plain object. Returns `null` for anything else, an array included. */
function asObject(value: unknown): Record<string, unknown> | null {
	return typeof value === "object" && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

/** Reads a value as a string that holds something. Returns `null` for anything else. */
function asText(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

/** Reads a base64url string as bytes. Returns `null` for anything else, and for text that is not base64url. */
function asBytes(value: unknown): Uint8Array | null {
	if (typeof value !== "string" || value.length === 0) {
		return null;
	}
	try {
		return decodeBase64Url(value);
	} catch {
		return null;
	}
}

/** Compares two byte strings. The values here are public, so the comparison needs no constant time. */
function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
	return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

/** Hashes bytes with SHA-256. */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
	return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

/** The client data the user agent signed, WebAuthn level 3 section 5.8.1. */
interface WebAuthnClientData {
	/** `webauthn.create` for a registration, `webauthn.get` for an authentication. */
	type: string;
	/** The challenge of the ceremony, in base64url. */
	challenge: string;
	/** The origin the ceremony ran on, the scheme, the host and the port. */
	origin: string;
	/** Whether the ceremony ran in a frame that is not same origin with the page around it. */
	crossOrigin?: boolean;
}

/** The fields of the authenticator data this component reads, WebAuthn level 3 sections 6.1 and 6.5.1. */
interface WebAuthnAuthenticatorData {
	/** The SHA-256 hash of the relying party id the credential is scoped to. */
	rpIdHash: Uint8Array;
	/** The flags byte. */
	flags: number;
	/** The signature counter of the authenticator, a 32-bit unsigned big-endian integer. */
	signCount: number;
	/** The identifier of the model of the authenticator, in hex. A registration carries it, an authentication does not. */
	aaguid?: string;
	/** The credential id. A registration carries it, an authentication does not. */
	credentialId?: Uint8Array;
}

/**
 * Reads the authenticator data. The structure describes its own length, so the method reads the attested credential
 * data only when the `AT` flag announces it.
 * @returns The fields the component reads, or `null` for a structure that is too short or that announces a credential
 * id it does not hold.
 */
function parseAuthenticatorData(bytes: Uint8Array): WebAuthnAuthenticatorData | null {
	if (bytes.length < 37) {
		return null;
	}
	const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
	const data: WebAuthnAuthenticatorData = {
		rpIdHash: bytes.subarray(0, 32),
		flags: bytes[32],
		signCount: view.getUint32(33),
	};
	if ((data.flags & FLAG_ATTESTED_CREDENTIAL_DATA) === 0) {
		return data;
	}
	if (bytes.length < 55) {
		return null;
	}
	const length = view.getUint16(53);
	if (length === 0 || length > CREDENTIAL_ID_LIMIT || bytes.length < 55 + length) {
		return null;
	}
	data.aaguid = encodeHex(bytes.subarray(37, 53));
	data.credentialId = bytes.subarray(55, 55 + length);
	return data;
}

/**
 * Turns an ASN.1 DER `Ecdsa-Sig-Value` into the pair of fixed-length integers that `crypto.subtle` reads. The DER
 * form writes each integer without its leading zero bytes, and it adds one when the first byte would read as a sign.
 * @param coordinate The length in bytes of one integer, which the curve fixes.
 * @returns The two integers, each padded to `coordinate` bytes, or `null` for a structure that does not read.
 */
function parseEcdsaSignature(signature: Uint8Array, coordinate: number): Uint8Array | null {
	if (signature.length < 8 || signature[0] !== 0x30) {
		return null;
	}
	// A sequence longer than 127 bytes writes its length over more than one byte. The P-521 curve reaches that.
	let offset = (signature[1] & 0x80) === 0 ? 2 : 2 + (signature[1] & 0x7f);
	const raw = new Uint8Array(coordinate * 2);
	for (const half of [0, 1]) {
		if (signature[offset] !== 0x02) {
			return null;
		}
		const length = signature[offset + 1];
		let start = offset + 2;
		const end = start + length;
		if (length === 0 || end > signature.length) {
			return null;
		}
		while (start < end - 1 && signature[start] === 0) {
			start++;
		}
		if (end - start > coordinate) {
			return null;
		}
		raw.set(signature.subarray(start, end), (half + 1) * coordinate - (end - start));
		offset = end;
	}
	return offset === signature.length ? raw : null;
}

/** What the component wrote to the key value store when it built the prompt of the ceremony in progress. */
interface WebAuthnCeremony {
	/** `webauthn.create` for a registration, `webauthn.get` for an authentication. */
	type: string;
	/** The challenge the prompt carried, in base64url. */
	challenge: string;
	/** The user handle the registration prompt carried, in base64url. An authentication prompt carries none. */
	handle?: string;
}

/** What the store holds about one credential under `data`. */
interface WebAuthnRecord {
	/** The public key of the credential, DER `SubjectPublicKeyInfo` in base64url. */
	publicKey: string;
	/** The COSE identifier of the algorithm that signs with the key. */
	algorithm: number;
	/** The last signature counter the component accepted. */
	signCount: number;
	/** The identifier of the model of the authenticator, in hex. */
	aaguid: string;
	/** How the client reaches the authenticator: `usb`, `nfc`, `ble`, `hybrid` or `internal`. */
	transports: string[];
	/** The user handle the authenticator holds beside the credential, in base64url. */
	userHandle: string;
	/** Whether the credential may leave the authenticator that made it. */
	backupEligible: boolean;
	/** Whether a copy of the credential rests outside the authenticator that made it. */
	backupState: boolean;
	/** Whether the owner ever verified themself to the authenticator with this credential. */
	uvInitialized: boolean;
}

/** The relying party the credentials belong to. One credential answers to one relying party and to nobody else. */
export interface WebAuthnRelyingParty {
	/**
	 * The domain the credentials are scoped to, `example.com` for one. It must be the domain of the page that runs
	 * the ceremony, or a parent of it. It never carries a scheme or a port.
	 */
	id: string;
	/** The name the client shows beside the account in a passkey manager. */
	name: string;
}

/** How the client names the owner in a passkey manager. Neither field reaches the signature. */
export interface WebAuthnUser {
	/** The name of the account, an address for one. */
	name: string;
	/** The name a human reads. */
	displayName: string;
}

/** Options for {@link WebAuthnAuthDanceComponent}. Only `rp` has no default. */
export interface WebAuthnAuthDanceComponentOptions {
	/** The relying party the credentials belong to. A change of `rp.id` makes every enrolled credential unusable. */
	rp: WebAuthnRelyingParty;
	/**
	 * The origins the component accepts in the client data, `https://example.com` for one. Give every origin that
	 * serves the page, a native application included.
	 * @defaultValue `["https://" + rp.id]`
	 */
	origins?: string[];
	/**
	 * The COSE identifiers of the algorithms the component asks for, in the order it prefers them. The component
	 * verifies `-7`, `-8`, `-35`, `-36`, `-37`, `-38`, `-39`, `-257`, `-258` and `-259`.
	 * @defaultValue `[-7, -257]`
	 */
	algorithms?: number[];
	/**
	 * Whether the owner must verify themself to the authenticator, with a fingerprint or a PIN for one. `required`
	 * makes one credential a factor of its own.
	 * @defaultValue `"preferred"`
	 */
	userVerification?: "required" | "preferred" | "discouraged";
	/**
	 * Whether the authenticator keeps the credential itself. A sign-in gives the authenticator no credential id, so
	 * only a credential the authenticator keeps signs a sign-in.
	 * @defaultValue `"required"`
	 */
	residentKey?: "required" | "preferred" | "discouraged";
	/** Which authenticators the client offers: the ones built into the client device, or the ones the owner carries. */
	authenticatorAttachment?: "platform" | "cross-platform";
	/**
	 * What the component asks the authenticator to say about its own model. The component reads no attestation
	 * statement, so keep the default.
	 * @defaultValue `"none"`
	 */
	attestation?: "none" | "indirect" | "direct" | "enterprise";
	/** How long the client waits for the authenticator, in milliseconds. @defaultValue `60000` */
	timeout?: number;
	/** How long a challenge stays valid, in seconds. @defaultValue `300` */
	ttl?: number;
	/**
	 * Whether a signature counter that does not go up refuses the answer. A counter that goes down is a signal that
	 * a copy of the credential exists, WebAuthn level 3 section 6.1.1. Many authenticators always report zero, and
	 * the component makes no comparison at all in that case.
	 * @defaultValue `true`
	 */
	cloneDetection?: boolean;
	/**
	 * What the client shows the owner in a passkey manager. Without it the component reads the first confirmed
	 * identification of the identity, and it falls back to `rp.name`.
	 *
	 * A sign-up builds its prompt before the library holds an identity, so give this option to name the owner in a
	 * sign-up.
	 */
	user?: (context: AuthDanceComponentContext) => WebAuthnUser | Promise<WebAuthnUser>;
}

/**
 * A public key credential, the WebAuthn of the W3C. The owner keeps the private key in an authenticator, a passkey
 * manager or a security key for one, and the store holds nothing but the public key.
 *
 * The component collects a credential and it verifies a signature, and the type of the prompt names what the flow
 * asks the client for:
 *
 * - A `sign-up`, an `enroll`, a `rotate` and the reset of a `recover` collect a credential, through a prompt of the
 *   type `webauthn-create`. `options.publicKey` of that prompt is a `PublicKeyCredentialCreationOptionsJSON`. The
 *   client passes it to `PublicKeyCredential.parseCreationOptionsFromJSON`, calls `navigator.credentials.create`,
 *   and submits `credential.toJSON()`.
 * - The component is verifiable, so each of those flows then asks the client for a signature of the credential it
 *   just collected, through a prompt of the type `webauthn`. Until that signature lands the record stays
 *   unconfirmed.
 * - A `sign-in`, and the first step of a `recover`, ask for a signature with the same prompt type `webauthn`.
 *   `options.publicKey` is a `PublicKeyCredentialRequestOptionsJSON` for `navigator.credentials.get`.
 *
 * The component is an `identification`, and the credential id is the value that names the owner. A sign-in
 * therefore needs no address and no name: the client answers with a signature, and the component reads the owner
 * out of the credential id. The library builds a sign-in prompt without an identity, so that prompt names no
 * credential and only a credential the authenticator keeps answers it. Keep `residentKey` at `required`.
 *
 * The store holds the public key, the algorithm, the model of the authenticator and the transports under `data`,
 * which `/list-components` drops. None of it opens an account: a signature does, and only the authenticator makes
 * one.
 *
 * The component reads no attestation statement. It therefore takes the public key of a registration from the
 * client, and it proves nothing about the model of the authenticator. This is the trust on first use that the
 * WebAuthn specification describes for a registration: the flow around the registration says who the owner is, and
 * the signature the component then asks for says that the credential works. An attestation statement answers a
 * different question, which is which model of authenticator holds the private key.
 *
 * The component keeps two records in the key value store:
 *
 * - `webauthn/<stateId>/<name>` holds the challenge of the ceremony in progress, for the time to live. `getPrompt`
 *   writes it, and a second call to `getPrompt` replaces it, so the last prompt the client read is the one that
 *   answers.
 * - `webauthn/count/<credentialId>` holds the last signature counter the component accepted. It has no time to
 *   live. Remove it when the credential leaves the identity.
 *
 * @example
 * ```ts
 * const components = {
 *     webauthn: new WebAuthnAuthDanceComponent({ rp: { id: "example.com", name: "Example" } }),
 * };
 * ```
 */
export class WebAuthnAuthDanceComponent implements AuthDanceComponent {
	/** The record kind the component contributes to an identity. The credential id resolves the owner on its own. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "identification";
	/** A credential proves control of itself with a signature, so `verificationComponent` returns the component that asks for one. */
	readonly verifiable = true;

	#options: WebAuthnAuthDanceComponentOptions;
	#origins: string[];
	#algorithms: number[];
	// Whether this instance is the verification `verificationComponent` returns. It always asks for a signature.
	#validation = false;

	/**
	 * Keeps the relying party and the shape of the ceremonies.
	 *
	 * @param options `rp` names the relying party. Every other key has a default.
	 * @throws {@link Error} When `algorithms` names a COSE identifier the component cannot verify.
	 */
	constructor(options: WebAuthnAuthDanceComponentOptions) {
		this.#options = options;
		this.#origins = options.origins ?? [`https://${options.rp.id}`];
		this.#algorithms = options.algorithms ?? [-7, -257];
		const unknown = this.#algorithms.filter((algorithm) => !(algorithm in ALGORITHMS));
		if (unknown.length > 0) {
			throw new Error(`webauthn cannot verify the COSE algorithms ${unknown.join(", ")}`);
		}
	}

	// The key that holds the challenge of the ceremony in progress. One dance, one step, one challenge.
	#ceremonyKey(context: AuthDanceComponentContext): string {
		return `webauthn/${context.stateId}/${context.name}`;
	}

	// Mints a challenge of 32 bytes and keeps it beside the type of the ceremony it belongs to.
	async #startCeremony(context: AuthDanceComponentContext, type: string, handle?: string): Promise<WebAuthnCeremony> {
		const ceremony: WebAuthnCeremony = { type, challenge: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))), handle };
		await context.storage.setKv(this.#ceremonyKey(context), JSON.stringify(ceremony), this.#options.ttl ?? 300);
		return ceremony;
	}

	// The ceremony the last prompt started. Returns `null` once the time to live passes.
	async #ceremony(context: AuthDanceComponentContext): Promise<WebAuthnCeremony | null> {
		const raw = await context.storage.getKv(this.#ceremonyKey(context));
		if (!raw) {
			return null;
		}
		try {
			const parsed = asObject(JSON.parse(raw));
			const type = asText(parsed?.type);
			const challenge = asText(parsed?.challenge);
			return type && challenge ? { type, challenge, handle: asText(parsed?.handle) ?? undefined } : null;
		} catch {
			return null;
		}
	}

	// Every credential the identity holds under the name of the step. A sign-in carries no identity, so it holds none.
	#records(context: AuthDanceComponentContext): AuthDanceIdentityIdentification[] {
		return (context.identity?.components ?? [])
			.filter((c): c is AuthDanceIdentityIdentification => c.kind === "identification" && c.component === context.name);
	}

	// Which credentials may answer the prompt. A flow that just collected one puts it in front of the stored ones,
	// and it is the only credential that confirms itself. Every other case takes any credential of the owner.
	#allowed(context: AuthDanceComponentContext): AuthDanceIdentityIdentification[] {
		const records = this.#records(context);
		const collected = records.find((record) => !record.confirmed);
		return collected ? [collected] : records.filter((record) => record.confirmed);
	}

	// Reads the `data` bag of a record, with a default for a field an older record omits.
	#data(record: AuthDanceIdentityIdentification): WebAuthnRecord | null {
		const data = record.data;
		const publicKey = asText(data?.publicKey);
		if (!publicKey || typeof data?.algorithm !== "number") {
			return null;
		}
		return {
			publicKey,
			algorithm: data.algorithm,
			signCount: typeof data.signCount === "number" ? data.signCount : 0,
			aaguid: asText(data.aaguid) ?? "",
			transports: Array.isArray(data.transports) ? data.transports.filter((t): t is string => typeof t === "string") : [],
			userHandle: asText(data.userHandle) ?? "",
			backupEligible: data.backupEligible === true,
			backupState: data.backupState === true,
			uvInitialized: data.uvInitialized === true,
		};
	}

	// A registration asks the client to make a credential. Every other case asks it to sign with one. The library
	// builds the prompt of a sign-in, and the first prompt of a recovery, without an identity. Both ask for a
	// signature. Every flow that collects a credential holds an identity by then, a sign-up excepted.
	#signs(context: AuthDanceComponentContext): boolean {
		return this.#validation || context.flow === "sign-in" || (context.flow === "recover" && !context.identity);
	}

	// What the client shows the owner in a passkey manager.
	async #user(context: AuthDanceComponentContext): Promise<WebAuthnUser> {
		if (this.#options.user) {
			return await this.#options.user(context);
		}
		const identification = (context.identity?.components ?? [])
			.find((c): c is AuthDanceIdentityIdentification => c.kind === "identification" && c.component !== context.name && c.confirmed);
		const name = identification?.identification ?? context.identity?.id ?? this.#options.rp.name;
		const data = context.identity?.data;
		return { name, displayName: asText(data?.name) ?? name };
	}

	// The entries of `excludeCredentials` and of `allowCredentials`.
	#descriptors(records: AuthDanceIdentityIdentification[]): Array<Record<string, unknown>> {
		return records.map((record) => {
			const transports = this.#data(record)?.transports ?? [];
			return { type: "public-key", id: record.identification, ...(transports.length > 0 ? { transports } : {}) };
		});
	}

	/**
	 * Describes the entry the client renders, under the component name. The type names what the client does:
	 * `webauthn-create` for a credential the client makes, `webauthn` for a signature it makes with one.
	 *
	 * `options.publicKey` carries the whole argument of the call, as the JSON form of the WebAuthn specification
	 * writes it. The method mints the challenge and keeps it under `webauthn/<stateId>/<name>`, so a second call
	 * replaces the challenge of the first, and only the last prompt the client read answers.
	 *
	 * The input is not sendable, because no channel delivers a signature.
	 * @returns One input for the client to render.
	 */
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		if (this.#signs(context)) {
			const ceremony = await this.#startCeremony(context, "webauthn.get");
			return {
				kind: "input",
				name: context.name,
				type: "webauthn",
				sendable: false,
				options: {
					publicKey: {
						challenge: ceremony.challenge,
						rpId: this.#options.rp.id,
						timeout: this.#options.timeout ?? 60_000,
						userVerification: this.#options.userVerification ?? "preferred",
						allowCredentials: this.#descriptors(this.#allowed(context)),
					},
				},
			};
		}
		// The identity of a sign-up reaches `getIdentityComponent`, never this method, so a sign-up gives the
		// credential a handle of its own. The credential id resolves the owner, and the handle never does.
		const handle = context.identity?.id
			? encodeBase64Url(new TextEncoder().encode(context.identity.id))
			: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
		const [ceremony, user] = await Promise.all([this.#startCeremony(context, "webauthn.create", handle), this.#user(context)]);
		return {
			kind: "input",
			name: context.name,
			type: "webauthn-create",
			sendable: false,
			options: {
				publicKey: {
					rp: { id: this.#options.rp.id, name: this.#options.rp.name },
					user: { id: handle, name: user.name, displayName: user.displayName },
					challenge: ceremony.challenge,
					pubKeyCredParams: this.#algorithms.map((alg) => ({ type: "public-key", alg })),
					timeout: this.#options.timeout ?? 60_000,
					excludeCredentials: this.#descriptors(this.#records(context)),
					authenticatorSelection: {
						residentKey: this.#options.residentKey ?? "required",
						requireResidentKey: (this.#options.residentKey ?? "required") === "required",
						userVerification: this.#options.userVerification ?? "preferred",
						...(this.#options.authenticatorAttachment ? { authenticatorAttachment: this.#options.authenticatorAttachment } : {}),
					},
					attestation: this.#options.attestation ?? "none",
				},
			},
		};
	}

	// The checks the client data of both ceremonies goes through, WebAuthn level 3 sections 7.1 and 7.2.
	#verifyClientData(bytes: Uint8Array, type: string, challenge: string): boolean {
		let data: WebAuthnClientData | null;
		try {
			data = asObject(JSON.parse(new TextDecoder().decode(bytes))) as WebAuthnClientData | null;
		} catch {
			return false;
		}
		if (!data || data.type !== type || data.challenge !== challenge) {
			return false;
		}
		// A ceremony inside a frame of another origin is refused, whatever the origin of that frame is.
		return this.#origins.includes(data.origin) && data.crossOrigin !== true;
	}

	// The checks the authenticator data of both ceremonies goes through.
	async #verifyAuthenticatorData(data: WebAuthnAuthenticatorData): Promise<boolean> {
		if (!equalBytes(data.rpIdHash, await sha256(new TextEncoder().encode(this.#options.rp.id)))) {
			return false;
		}
		if ((data.flags & FLAG_USER_PRESENT) === 0) {
			return false;
		}
		if ((this.#options.userVerification ?? "preferred") === "required" && (data.flags & FLAG_USER_VERIFIED) === 0) {
			return false;
		}
		// A credential that may not leave its authenticator cannot rest anywhere else.
		return (data.flags & FLAG_BACKUP_ELIGIBLE) !== 0 || (data.flags & FLAG_BACKUP_STATE) === 0;
	}

	// Reads the stored public key. The method throws nothing: a key the runtime refuses gives `null`.
	async #importKey(record: WebAuthnRecord): Promise<CryptoKey | null> {
		const algorithm = ALGORITHMS[record.algorithm];
		const key = asBytes(record.publicKey);
		if (!algorithm || !key) {
			return null;
		}
		try {
			return await crypto.subtle.importKey("spki", key as BufferSource, algorithm.key, false, ["verify"]);
		} catch {
			return null;
		}
	}

	// Checks the signature over the authenticator data and the hash of the client data, WebAuthn level 3 section 7.2.
	async #verifySignature(record: WebAuthnRecord, authenticatorData: Uint8Array, clientData: Uint8Array, signature: Uint8Array) {
		const algorithm = ALGORITHMS[record.algorithm];
		const key = await this.#importKey(record);
		if (!algorithm || !key) {
			return false;
		}
		const raw = algorithm.coordinate > 0 ? parseEcdsaSignature(signature, algorithm.coordinate) : signature;
		if (!raw) {
			return false;
		}
		const hash = await sha256(clientData);
		const signed = new Uint8Array(authenticatorData.length + hash.length);
		signed.set(authenticatorData);
		signed.set(hash, authenticatorData.length);
		try {
			return await crypto.subtle.verify(algorithm.verify, key, raw as BufferSource, signed as BufferSource);
		} catch {
			return false;
		}
	}

	/**
	 * Turns the answer of `navigator.credentials.create` into the identification record the identity holds. The
	 * `sign-up`, `enroll`, `rotate` and `recover` flows call this method.
	 *
	 * The record starts unconfirmed, and the signature of the verification confirms it. `identification` holds the
	 * credential id, and `data` holds the public key, the algorithm, the model of the authenticator, the
	 * transports and the user handle.
	 * @param component The component name the record carries.
	 * @param value The `RegistrationResponseJSON` of the client, as `PublicKeyCredential.toJSON` writes it.
	 * @param confirmed Whether the record starts as confirmed.
	 * @returns One identification record.
	 * @throws {@link InvalidPromptValueError} When no registration is in progress, when the answer does not read,
	 * when the client data or the authenticator data fails a check, when the algorithm is not one the component
	 * asked for, when the user agent reports no public key, and when the credential id already belongs to somebody.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		const ceremony = await this.#ceremony(context);
		if (!ceremony || ceremony.type !== "webauthn.create") {
			throw new InvalidPromptValueError("no webauthn registration is in progress");
		}
		const credential = asObject(value);
		const response = asObject(credential?.response);
		const id = asText(credential?.id);
		const rawId = asBytes(credential?.rawId ?? credential?.id);
		const clientData = asBytes(response?.clientDataJSON);
		const authenticatorBytes = asBytes(response?.authenticatorData);
		if (credential?.type !== "public-key" || !id || !rawId || !clientData || !authenticatorBytes) {
			throw new InvalidPromptValueError("webauthn registration must be a RegistrationResponseJSON");
		}
		if (rawId.length > CREDENTIAL_ID_LIMIT || encodeBase64Url(rawId) !== id) {
			throw new InvalidPromptValueError("webauthn credential id does not read");
		}
		if (!this.#verifyClientData(clientData, "webauthn.create", ceremony.challenge)) {
			throw new InvalidPromptValueError("webauthn client data does not match the registration in progress");
		}
		const authenticatorData = parseAuthenticatorData(authenticatorBytes);
		if (!authenticatorData || !authenticatorData.credentialId || !await this.#verifyAuthenticatorData(authenticatorData)) {
			throw new InvalidPromptValueError("webauthn authenticator data does not pass its checks");
		}
		// The credential id the authenticator signed and the one the client reports are the same value.
		if (!equalBytes(authenticatorData.credentialId, rawId)) {
			throw new InvalidPromptValueError("webauthn credential id does not match the attested credential data");
		}
		const algorithm = typeof response?.publicKeyAlgorithm === "number" ? response.publicKeyAlgorithm : NaN;
		if (!this.#algorithms.includes(algorithm)) {
			throw new InvalidPromptValueError(`webauthn credential carries the algorithm ${algorithm}, which the component did not ask for`);
		}
		const publicKey = asText(response?.publicKey);
		const record: WebAuthnRecord = {
			publicKey: publicKey ?? "",
			algorithm,
			signCount: authenticatorData.signCount,
			aaguid: authenticatorData.aaguid ?? "",
			transports: Array.isArray(response?.transports) ? response.transports.filter((t): t is string => typeof t === "string") : [],
			userHandle: ceremony.handle ?? "",
			backupEligible: (authenticatorData.flags & FLAG_BACKUP_ELIGIBLE) !== 0,
			backupState: (authenticatorData.flags & FLAG_BACKUP_STATE) !== 0,
			uvInitialized: (authenticatorData.flags & FLAG_USER_VERIFIED) !== 0,
		};
		// A key that does not read here would refuse every signature later, so the failure lands on the step that
		// collected it.
		if (!publicKey || !await this.#importKey(record)) {
			throw new InvalidPromptValueError("webauthn public key does not read as a DER SubjectPublicKeyInfo");
		}
		// A credential id belongs to one owner. WebAuthn level 3 section 7.1 refuses a registration that repeats one.
		const taken = this.#records(context).some((c) => c.identification === id) ||
			await context.storage.getIdentityByIdentification(component, id).then((i) => !!i).catch(() => false);
		if (taken) {
			throw new InvalidPromptValueError("webauthn credential id already belongs to an identity");
		}
		await context.storage.unsetKv(this.#ceremonyKey(context));
		return [
			{
				kind: "identification",
				component,
				identification: id,
				confirmed,
				data: { ...record },
			},
		];
	}

	/**
	 * Checks the answer of `navigator.credentials.get` against the credential the id of the answer names.
	 *
	 * The method reads the challenge of the prompt, the origin, the relying party, the presence of the owner, the
	 * signature over the authenticator data and the hash of the client data, and the signature counter. It then
	 * drops the challenge, so one prompt answers one time.
	 *
	 * A verification accepts the credential the flow just collected, and nothing else. Every other case accepts any
	 * confirmed credential of the owner, and it reads the owner out of the credential id.
	 * @param response The `AuthenticationResponseJSON` of the client, as `PublicKeyCredential.toJSON` writes it.
	 * @param context The context of the dance, which carries the identity when the library holds one.
	 * @returns The id of the identity that owns the credential. `true` from the verification of a credential the
	 * flow just collected. `false` in every other case, which includes an answer that does not read, a challenge
	 * that expired, a credential nobody holds and a signature counter that did not go up.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const ceremony = await this.#ceremony(context);
		if (!ceremony || ceremony.type !== "webauthn.get") {
			return false;
		}
		const credential = asObject(response);
		const answer = asObject(credential?.response);
		const id = asText(credential?.id);
		const clientData = asBytes(answer?.clientDataJSON);
		const authenticatorBytes = asBytes(answer?.authenticatorData);
		const signature = asBytes(answer?.signature);
		if (credential?.type !== "public-key" || !id || !clientData || !authenticatorBytes || !signature) {
			return false;
		}
		// The identity in the context holds the credential the flow just collected, which no store holds yet. A
		// sign-in carries no identity at all, and the credential id names the owner.
		const known = this.#records(context).find((c) => c.identification === id);
		const identity = known ? context.identity : await context.storage.getIdentityByIdentification(context.name, id).catch(() => undefined);
		const stored = known ?? identity?.components
			.find((c): c is AuthDanceIdentityIdentification =>
				c.kind === "identification" && c.component === context.name && c.identification === id
			);
		if (!identity || !stored) {
			return false;
		}
		if (this.#validation ? !this.#allowed(context).includes(stored) : !stored.confirmed) {
			return false;
		}
		const record = this.#data(stored);
		if (!record) {
			return false;
		}
		const userHandle = asText(answer?.userHandle);
		if (userHandle && record.userHandle && userHandle !== record.userHandle) {
			return false;
		}
		if (!this.#verifyClientData(clientData, "webauthn.get", ceremony.challenge)) {
			return false;
		}
		const authenticatorData = parseAuthenticatorData(authenticatorBytes);
		if (!authenticatorData || !await this.#verifyAuthenticatorData(authenticatorData)) {
			return false;
		}
		if (!await this.#verifySignature(record, authenticatorBytes, clientData, signature)) {
			return false;
		}
		if (!await this.#countSignature(context, id, record, authenticatorData.signCount)) {
			return false;
		}
		await context.storage.unsetKv(this.#ceremonyKey(context));
		return this.#validation ? true : identity.id;
	}

	// The signature counter of the authenticator. The store holds the last accepted value under
	// `webauthn/count/<credentialId>`, because the component writes no identity of its own.
	async #countSignature(
		context: AuthDanceComponentContext,
		id: string,
		record: WebAuthnRecord,
		signCount: number,
	): Promise<boolean> {
		const key = `webauthn/count/${id}`;
		const seen = Number(await context.storage.getKv(key));
		const previous = Number.isFinite(seen) ? Math.max(seen, record.signCount) : record.signCount;
		// An authenticator that keeps no counter reports zero every time, and the comparison does not apply.
		if (signCount === 0 && previous === 0) {
			return true;
		}
		if (signCount <= previous && (this.#options.cloneDetection ?? true)) {
			return false;
		}
		if (signCount > previous) {
			await context.storage.setKv(key, signCount.toString());
		}
		return true;
	}

	/**
	 * Builds the component that proves control of the collected credential. It asks the client for a signature,
	 * with the same relying party, and it names that one credential in `allowCredentials`.
	 * @returns The component that asks for the signature. Its prompt carries the type `webauthn`.
	 */
	// deno-lint-ignore require-await
	async verificationComponent(_context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		const component = new WebAuthnAuthDanceComponent(this.#options);
		component.#validation = true;
		return component;
	}
}
