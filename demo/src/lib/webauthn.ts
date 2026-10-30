// The WebAuthn component sends `PublicKeyCredentialCreationOptionsJSON` or `PublicKeyCredentialRequestOptionsJSON`
// under `options.publicKey`, and takes back the JSON form of the credential. Browsers that lack the JSON helpers of
// WebAuthn Level 3 get the same shapes from the conversions below.

type Json = Record<string, any>;

function toBytes(value: string): Uint8Array<ArrayBuffer> {
	const base64 = value
		.replace(/-/g, "+")
		.replace(/_/g, "/")
		.padEnd(Math.ceil(value.length / 4) * 4, "=");
	return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

function toBase64Url(buffer: ArrayBuffer | ArrayBufferView | null | undefined): string | undefined {
	if (!buffer) {
		return undefined;
	}
	const bytes =
		buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
	return btoa(String.fromCharCode(...bytes))
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
}

function descriptors(list: Json[] | undefined): PublicKeyCredentialDescriptor[] | undefined {
	return list?.map((descriptor) => ({ ...descriptor, type: "public-key", id: toBytes(descriptor.id) }) as PublicKeyCredentialDescriptor);
}

function serialize(credential: PublicKeyCredential): Json {
	if (typeof credential.toJSON === "function") {
		return credential.toJSON();
	}
	const response = credential.response as Json;
	return {
		id: credential.id,
		rawId: toBase64Url(credential.rawId),
		type: credential.type,
		authenticatorAttachment: credential.authenticatorAttachment,
		clientExtensionResults: credential.getClientExtensionResults(),
		response:
			"attestationObject" in response
				? {
						clientDataJSON: toBase64Url(response.clientDataJSON),
						attestationObject: toBase64Url(response.attestationObject),
						authenticatorData: toBase64Url(response.getAuthenticatorData()),
						publicKey: toBase64Url(response.getPublicKey()),
						publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
						transports: response.getTransports(),
					}
				: {
						clientDataJSON: toBase64Url(response.clientDataJSON),
						authenticatorData: toBase64Url(response.authenticatorData),
						signature: toBase64Url(response.signature),
						userHandle: toBase64Url(response.userHandle),
					},
	};
}

/** Whether this browser can run a WebAuthn ceremony at all. */
export function webauthnSupported(): boolean {
	return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function";
}

/** Registers a new passkey with the options of a `webauthn-create` prompt. */
export async function createPasskey(options: Json): Promise<Json> {
	const publicKey = options.publicKey as Json;
	const credential = (await navigator.credentials.create({
		publicKey: {
			...publicKey,
			challenge: toBytes(publicKey.challenge),
			user: { ...publicKey.user, id: toBytes(publicKey.user.id) },
			excludeCredentials: descriptors(publicKey.excludeCredentials),
		} as unknown as PublicKeyCredentialCreationOptions,
	})) as PublicKeyCredential | null;
	if (!credential) {
		throw new Error("The passkey was not created");
	}
	return serialize(credential);
}

/** Signs the challenge of a `webauthn` prompt with a passkey. */
export async function signWithPasskey(options: Json): Promise<Json> {
	const publicKey = options.publicKey as Json;
	const credential = (await navigator.credentials.get({
		publicKey: {
			...publicKey,
			challenge: toBytes(publicKey.challenge),
			allowCredentials: descriptors(publicKey.allowCredentials),
		} as unknown as PublicKeyCredentialRequestOptions,
	})) as PublicKeyCredential | null;
	if (!credential) {
		throw new Error("No passkey answered");
	}
	return serialize(credential);
}
