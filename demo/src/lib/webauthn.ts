/**
 * @module
 *
 * What the browser does between the prompt and the answer. The library speaks the JSON form of the WebAuthn
 * specification: base64url strings where the API wants buffers. This module walks the prompt one way and the
 * credential the other way.
 *
 * {@link runCeremony} is what the submit button runs. It must stay reachable from the click without an `await` in
 * front of it, because `navigator.credentials.create` asks for a gesture of the owner and an `await` spends it.
 *
 * A recent browser does the same through `PublicKeyCredential.parseCreationOptionsFromJSON`,
 * `PublicKeyCredential.parseRequestOptionsFromJSON` and `credential.toJSON()`. The conversions are written out here
 * because they are the whole contract between this page and the component, and they are worth reading.
 */

import type { AuthDancePromptInput } from "auth-dance";

/** Reads a base64url string as bytes. */
function fromBase64Url(value: string): Uint8Array {
	const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
	const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Writes bytes as a base64url string, without the padding. */
function toBase64Url(buffer: ArrayBuffer): string {
	let binary = "";
	for (const byte of new Uint8Array(buffer)) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

/** One credential the prompt names, in `excludeCredentials` or in `allowCredentials`. */
interface DescriptorJSON {
	/** Always `public-key`. */
	type: string;
	/** The credential id, in base64url. */
	id: string;
	/** How the client reaches the authenticator: `usb`, `nfc`, `ble`, `hybrid` or `internal`. */
	transports?: string[];
}

/** What `options.publicKey` of a `webauthn-create` prompt holds. */
export interface CreationOptionsJSON {
	/** The relying party the credential belongs to. */
	rp: { id: string; name: string };
	/** The owner, as the passkey manager shows them. `id` is the user handle, in base64url. */
	user: { id: string; name: string; displayName: string };
	/** The challenge of the ceremony, in base64url. */
	challenge: string;
	/** The algorithms the server accepts, by COSE identifier, in the order it prefers them. */
	pubKeyCredParams: Array<{ type: string; alg: number }>;
	/** How long the client waits for the authenticator, in milliseconds. */
	timeout?: number;
	/** The credentials the authenticator must not make a second time. */
	excludeCredentials?: DescriptorJSON[];
	/** What the client asks of the authenticator. */
	authenticatorSelection?: Record<string, unknown>;
	/** What the server asks the authenticator to say about its own model. */
	attestation?: string;
}

/** What `options.publicKey` of a `webauthn` prompt holds. */
export interface RequestOptionsJSON {
	/** The challenge of the ceremony, in base64url. */
	challenge: string;
	/** The domain the credential answers to. */
	rpId?: string;
	/** How long the client waits for the authenticator, in milliseconds. */
	timeout?: number;
	/** Whether the owner must verify themself to the authenticator. */
	userVerification?: string;
	/** The credentials that may answer. An empty list asks the authenticator for one it keeps itself. */
	allowCredentials?: DescriptorJSON[];
}

function descriptor(entry: DescriptorJSON): PublicKeyCredentialDescriptor {
	return {
		type: "public-key",
		id: fromBase64Url(entry.id) as BufferSource,
		...(entry.transports ? { transports: entry.transports as AuthenticatorTransport[] } : {}),
	};
}

/** Turns a `webauthn-create` prompt into the argument of `navigator.credentials.create`. */
export function creationOptions(json: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
	return {
		...json,
		challenge: fromBase64Url(json.challenge) as BufferSource,
		user: { ...json.user, id: fromBase64Url(json.user.id) as BufferSource },
		pubKeyCredParams: json.pubKeyCredParams.map((entry) => ({ type: "public-key" as const, alg: entry.alg })),
		excludeCredentials: (json.excludeCredentials ?? []).map(descriptor),
		authenticatorSelection: json.authenticatorSelection as AuthenticatorSelectionCriteria,
		attestation: json.attestation as AttestationConveyancePreference,
	};
}

/** Turns a `webauthn` prompt into the argument of `navigator.credentials.get`. */
export function requestOptions(json: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
	return {
		...json,
		challenge: fromBase64Url(json.challenge) as BufferSource,
		userVerification: json.userVerification as UserVerificationRequirement,
		allowCredentials: (json.allowCredentials ?? []).map(descriptor),
	};
}

/** The head of both answers: what names the credential, whatever ceremony made it. */
function head(credential: PublicKeyCredential): Record<string, unknown> {
	return {
		id: credential.id,
		rawId: toBase64Url(credential.rawId),
		type: credential.type,
		authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
		clientExtensionResults: credential.getClientExtensionResults(),
	};
}

/**
 * The `RegistrationResponseJSON` the component collects. `publicKey` is the whole point of the answer, and a browser
 * that understands none of the algorithms the server asked for reports none.
 */
export function registrationJSON(credential: PublicKeyCredential): Record<string, unknown> {
	const response = credential.response as AuthenticatorAttestationResponse;
	const publicKey = response.getPublicKey();
	return {
		...head(credential),
		response: {
			clientDataJSON: toBase64Url(response.clientDataJSON),
			attestationObject: toBase64Url(response.attestationObject),
			authenticatorData: toBase64Url(response.getAuthenticatorData()),
			transports: response.getTransports(),
			publicKey: publicKey ? toBase64Url(publicKey) : undefined,
			publicKeyAlgorithm: response.getPublicKeyAlgorithm(),
		},
	};
}

/** The `AuthenticationResponseJSON` the component verifies. The signature covers the authenticator data and the client data. */
export function authenticationJSON(credential: PublicKeyCredential): Record<string, unknown> {
	const response = credential.response as AuthenticatorAssertionResponse;
	return {
		...head(credential),
		response: {
			clientDataJSON: toBase64Url(response.clientDataJSON),
			authenticatorData: toBase64Url(response.authenticatorData),
			signature: toBase64Url(response.signature),
			userHandle: response.userHandle ? toBase64Url(response.userHandle) : undefined,
		},
	};
}

/** Whether this browser holds the API at all. A page served over plain HTTP, `localhost` excepted, holds none. */
export function webAuthnAvailable(): boolean {
	return typeof globalThis.PublicKeyCredential === "function" && !!navigator.credentials;
}

/** A plain sentence for what a refused ceremony threw. */
export function describeCeremonyFailure(cause: unknown): string {
	const name = cause instanceof Error ? cause.name : "";
	switch (name) {
		case "NotAllowedError":
			return "The ceremony was abandoned, or it ran out of time. Nothing reached the server.";
		case "InvalidStateError":
			return "This authenticator already holds a credential for this account. `excludeCredentials` named it, so it refused to make a second one.";
		case "NotSupportedError":
			return "The authenticator supports none of the algorithms the component asked for.";
		case "SecurityError":
			return "The relying party id does not match the origin of this page. A credential answers to one domain only.";
		case "AbortError":
			return "The ceremony was cancelled.";
		default:
			return cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause);
	}
}

/**
 * Runs the ceremony the prompt describes and answers with the value of the prompt.
 *
 * The method is the whole of what the client does: it turns the options into buffers, hands them to the
 * authenticator, and turns the answer back into the JSON the component reads. Call it without awaiting anything
 * first, or the browser no longer counts the click as a gesture of the owner.
 * @param prompt A prompt of the type `webauthn-create` or `webauthn`.
 * @returns The `RegistrationResponseJSON`, or the `AuthenticationResponseJSON`.
 * @throws {Error} When this browser holds no API, when the prompt carries no options, and when the authenticator
 * refuses. The message is a plain sentence, and it lands in the alert of the page.
 */
export function runCeremony(prompt: AuthDancePromptInput): Promise<Record<string, unknown>> {
	if (!webAuthnAvailable()) {
		return Promise.reject(new Error("This browser holds no Web Authentication API. It needs HTTPS, or `localhost`."));
	}
	const options = prompt.options?.publicKey as (CreationOptionsJSON & RequestOptionsJSON) | undefined;
	if (!options) {
		return Promise.reject(new Error("The prompt carries no publicKey options."));
	}
	// `create` makes a key pair and gives back the public half. `get` signs the challenge with a key pair the
	// authenticator already holds.
	const registering = prompt.type === "webauthn-create";
	const ceremony = registering
		? navigator.credentials.create({ publicKey: creationOptions(options) })
		: navigator.credentials.get({ publicKey: requestOptions(options) });
	return ceremony.then((credential) => {
		if (!credential) {
			throw new Error("The browser returned no credential.");
		}
		return registering ? registrationJSON(credential as PublicKeyCredential) : authenticationJSON(credential as PublicKeyCredential);
	}, (cause) => {
		throw new Error(describeCeremonyFailure(cause));
	});
}
