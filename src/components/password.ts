import type { AuthComponent, AuthComponentContext } from "../component.ts";
import type { Identity, IdentityComponent } from "../identity.ts";
import type { AuthPromptInput } from "../prompt.ts";
import { encodeBase64 } from "@std/encoding/base64";

export default class PasswordAuthComponent implements AuthComponent {
	readonly kind: IdentityComponent["kind"] = "challenge";
	readonly verifiable = false;
	#salt: string;

	constructor(salt: string) {
		this.#salt = salt;
	}

	/**
	 * Hashes a plain-text password using SHA-512 with the configured salt.
	 * @param password The plain-text password to hash.
	 * @returns A Base64-encoded SHA-512 hash string.
	 */
	async hashPassword(password: string): Promise<string> {
		return encodeBase64(
			await crypto.subtle.digest(
				"SHA-512",
				new TextEncoder().encode(`${this.#salt}:${password}`),
			),
		);
	}

	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean = false,
	): Promise<IdentityComponent[]> {
		const password = typeof value === "string" ? value : null;
		const hash = await this.hashPassword(password ?? "");
		return [
			{
				kind: "challenge",
				component,
				confirmed,
				data: { hash },
			},
		];
	}

	// deno-lint-ignore require-await
	async getPrompt(context: AuthComponentContext): Promise<AuthPromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "password",
			sendable: false,
		};
	}

	async verifyPrompt(response: unknown, context: AuthComponentContext): Promise<boolean | Identity["id"]> {
		const value = typeof response === "string" ? response : null;
		if (!value) {
			return false;
		}
		const hash = await this.hashPassword(value);
		return !!context.identity &&
			context.identity.components
				.some((c) => c.kind === "challenge" && c.component === context.name && c.data && c.data.hash === hash);
	}
}
