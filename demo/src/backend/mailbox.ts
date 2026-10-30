import { type AuthDanceIdentityChannel, type AuthDanceMessage, InvalidPromptValueError } from "auth-dance";
import { normalizeEmailAddress } from "auth-dance/components/email";
import { MemoryAuthDanceChannel } from "auth-dance/providers/memory";
import type { DemoDatabase } from "./storage.ts";

/** One message of the demo inbox. */
export interface DemoMail {
	id: string;
	at: string;
	to: string;
	subject: string;
	code?: string;
	text?: string;
}

/** The mail channel of the demo. It sends nothing, and keeps the last 50 messages for the inbox panel of the page. */
export class DemoMailbox extends MemoryAuthDanceChannel {
	#db: DemoDatabase;

	constructor(db: DemoDatabase) {
		super("email");
		this.#db = db;
	}

	/** The messages, the newest first. */
	async inbox(): Promise<DemoMail[]> {
		return (await this.#db.getAll("mail")).sort((a, b) => b.at.localeCompare(a.at));
	}

	async empty(): Promise<void> {
		await this.#db.clear("mail");
	}

	// The memory channel keeps the recipient as `sms`. This one carries mail.
	override async getIdentityChannel(channel: string, value: unknown, confirmed = false): Promise<AuthDanceIdentityChannel> {
		const email = normalizeEmailAddress(value);
		if (email === null) {
			throw new InvalidPromptValueError(`${channel} must be one email address`);
		}
		return { kind: "channel", component: channel, confirmed, data: { email } };
	}

	override async sendMessage(message: AuthDanceMessage): Promise<void> {
		const to = message.recipient.data?.email;
		const mail: DemoMail = {
			id: crypto.randomUUID(),
			at: new Date().toISOString(),
			to: typeof to === "string" ? to : JSON.stringify(message.recipient.data ?? {}),
			subject: message.subject,
			code: message.content["text/x-code"],
			text: message.content["text/plain"],
		};
		await this.#db.put("mail", mail);
		for (const old of (await this.inbox()).slice(50)) {
			await this.#db.delete("mail", old.id);
		}
		console.log(`[mail] ${mail.to}: ${mail.subject} (${mail.code ?? "no code"})`);
	}
}
