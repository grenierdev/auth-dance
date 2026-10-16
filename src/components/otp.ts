import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { ChannelNotSubscribedError, ComponentNotVerifiableError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityChannel, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDanceMessage } from "../message.ts";
import { otp } from "../otp.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

export interface OtpAuthDanceComponentOptions {
	channel: string;
	digits?: number;
	ttl?: number;
	subject?: Record<string, string | ((code: string, context: AuthDanceComponentContext) => string)>;
	html?: Record<string, string | ((code: string, context: AuthDanceComponentContext) => string)>;
	text?: Record<string, string | ((code: string, context: AuthDanceComponentContext) => string)>;
}

// What `sendPrompt` keeps under `otp/<stateId>/<name>`. The client holds the state and can replay an earlier one, and a
// replay keeps the same stateId. A replay can resolve another identity or collect another address, so the code alone
// proves nothing. The record also holds the identity and the recipient the code went to.
interface PendingCode {
	code: string;
	identityId: string;
	recipient: string;
}

// Who a code goes to: the channel the identity holds under the configured name, and the identity itself.
interface CodeTarget {
	channel: AuthDanceIdentityChannel;
	identityId: string;
	recipient: string;
}

/**
 * A one-time code that the library delivers over a channel. A verifiable component uses it to prove control of its own value.
 * `sendPrompt` writes the code to KV under `otp/<stateId>/<name>`, together with the identity and the recipient it goes to.
 * `verifyPrompt` accepts the code for that identity and that recipient only, and it deletes the key on a match, so a code
 * works one time only. The key-value store drops a code that nobody submits at the end of the time to live.
 */
export class OtpAuthDanceComponent implements AuthDanceComponent {
	/** The record kind the component contributes to an identity. A `challenge` proves a claim, and never resolves an identity. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/** This component has no verification of its own. */
	readonly verifiable = false;

	#options: OtpAuthDanceComponentOptions;

	/**
	 * @param options The name of the channel that delivers the code, the number of digits in a code (default `6`), and the time
	 * that a code stays valid, in seconds (default `300`). The identity must hold a channel with the given name.
	 */
	constructor(options: OtpAuthDanceComponentOptions) {
		this.#options = options;
	}

	/**
	 * Builds the challenge record this component contributes to an identity. The record holds no code.
	 * @param component The name of the step in the choreography.
	 * @param value What the owner submitted. The record keeps it under `data.recipient` without a type check.
	 * @param confirmed Whether the owner already proved control of the value. Defaults to `false`.
	 * @returns One challenge record.
	 */

	async getIdentityComponent(component: string, value: unknown, confirmed: boolean = false): Promise<AuthDanceIdentityComponent[]> {
		return [
			{
				kind: "challenge",
				component,
				confirmed,
				data: { recipient: value },
			},
		];
	}

	/** Describes the code entry the client renders. The prompt is sendable, so the client can ask for a fresh code. */

	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		return {
			kind: "input",
			name: context.name,
			type: "otp",
			sendable: true,
		};
	}

	/**
	 * Compares the submitted code with the one in KV, then deletes the key so a code works one time only. The code must
	 * also go to the same identity and the same recipient as the context names now.
	 * @returns `true` when the code matches. `false` in every other case, which includes an expired code, a used code, and
	 * a code that went to another identity or another recipient.
	 */
	async verifyPrompt(response: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		const value = typeof response === "string" ? response : null;
		if (!value) {
			return false;
		}
		const target = this.#target(context);
		const pending = await this.#pending(context);
		if (
			!target ||
			!pending ||
			pending.code !== value ||
			pending.identityId !== target.identityId ||
			pending.recipient !== target.recipient
		) {
			return false;
		}
		await context.storage.unsetKv(this.#key(context));
		return true;
	}

	/**
	 * Generates a code, stores it under `otp/<stateId>/<name>` for the time to live, and returns the message to deliver.
	 * The recipient is the channel that the identity holds under the configured channel name, and never a value from the
	 * client. `content["text/x-code"]` holds the code. The component ignores `locale`.
	 * @throws {@link ChannelNotSubscribedError} When the context carries no identity, or the identity holds no channel with
	 * the configured name.
	 */
	async sendPrompt(_locale: string, context: AuthDanceComponentContext): Promise<AuthDanceMessage> {
		const target = this.#target(context);
		if (!target) {
			throw new ChannelNotSubscribedError(this.#options.channel);
		}
		const code = otp({ digits: this.#options.digits ?? 6 });
		const pending: PendingCode = { code, identityId: target.identityId, recipient: target.recipient };
		await context.storage.setKv(this.#key(context), JSON.stringify(pending), this.#options.ttl ?? 300);
		const subject =
			this.#options.subject?.en instanceof Function
				? this.#options.subject?.en(code, context)
				: (this.#options.subject?.en ?? "Your one-time code");
		const text =
			this.#options.text?.en instanceof Function
				? this.#options.text?.en(code, context)
				: (this.#options.text?.en ?? `Your one-time code is: ${code}`);
		const html =
			this.#options.html?.en instanceof Function
				? this.#options.html?.en(code, context)
				: (this.#options.html?.en ?? `<p>Your one-time code is: <strong>${code}</strong></p>`);
		return {
			recipient: target.channel,
			subject,
			content: {
				"text/x-code": code,
				"text/plain": text,
				"text/html": html,
			},
		};
	}

	/**
	 * Always throws, because another component uses this one as its verification.
	 * @throws {@link ComponentNotVerifiableError} On every call. The message carries the step name.
	 */

	async verificationComponent?(context: AuthDanceComponentContext): Promise<AuthDanceComponent> {
		throw new ComponentNotVerifiableError(context.name);
	}

	// The key of the code that waits for this dance and this step.
	#key(context: AuthDanceComponentContext): string {
		return `otp/${context.stateId}/${context.name}`;
	}

	// `sendPrompt` and `verifyPrompt` both read the target from the context. A sign-up, an enroll, a rotate and a recover put
	// the collected channel first, so both calls read the new recipient. Returns `undefined` when the identity holds no
	// channel under the configured name.
	#target(context: AuthDanceComponentContext): CodeTarget | undefined {
		const channel = context.identity?.components.find(
			(c): c is AuthDanceIdentityChannel => c.kind === "channel" && c.component === this.#options.channel,
		);
		if (!context.identity || !channel) {
			return undefined;
		}
		return { channel, identityId: context.identity.id, recipient: JSON.stringify(channel.data ?? {}) };
	}

	// The code `sendPrompt` wrote for this dance and this step. Returns `null` once the time to live passes, and for a value
	// in another shape, for example a bare code that an earlier version of this component wrote.
	async #pending(context: AuthDanceComponentContext): Promise<PendingCode | null> {
		const raw = await context.storage.getKv(this.#key(context));
		if (!raw) {
			return null;
		}
		try {
			const parsed = JSON.parse(raw);
			return typeof parsed?.code === "string" && typeof parsed.identityId === "string" && typeof parsed.recipient === "string"
				? { code: parsed.code, identityId: parsed.identityId, recipient: parsed.recipient }
				: null;
		} catch {
			return null;
		}
	}
}
