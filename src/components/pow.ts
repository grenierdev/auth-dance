import type { AuthDanceComponent, AuthDanceComponentContext } from "../component.ts";
import { InvalidPromptValueError } from "../error.ts";
import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "../identity.ts";
import type { AuthDancePromptInput } from "../prompt.ts";

/** The digests that a proof of work can use. Each digest has a length that is a multiple of 32 bits. */
export type PowAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

/** Options for {@link PowAuthDanceComponent}. */
export interface PowAuthDanceComponentOptions {
	/**
	 * The number of leading zero bits that the digest of `challenge + nonce` must have. Each added bit doubles the
	 * mean work of the client.
	 * @defaultValue `16`
	 */
	difficulty?: number;
	/**
	 * The digest of the proof.
	 * @defaultValue `"SHA-256"`
	 */
	algorithm?: PowAlgorithm;
	/**
	 * The time that a challenge stays valid, in seconds.
	 * @defaultValue `300`
	 */
	ttl?: number;
}

/** The options of a prompt of the type `pow`. The client gives them to {@link work}. */
export interface PowPromptOptions {
	/** The random text that the client puts before the nonce. */
	challenge: string;
	/** The number of leading zero bits that the digest must have. */
	difficulty: number;
	/** The digest of the proof. */
	algorithm: PowAlgorithm;
}

/** The {@link work} function raises this error when its `signal` aborts the search. */
export class WorkAbortedError extends Error {}

// Finds the first nonce in `start`, `start + step`, `start + 2 * step`, ... whose digest has `difficulty` leading zero
// bits. It stops after `attempts` nonces, or when `signal` aborts, and then returns `undefined`.
//
// `work` sends the source of this function to each Web Worker, so the function must not read anything outside its own
// body. A bundler can rename a module-level name, and the worker would not find it.
async function search(
	challenge: string,
	difficulty: number,
	algorithm: string,
	start: number,
	step: number,
	attempts: number,
	signal?: AbortSignal,
): Promise<number | undefined> {
	const encoder = new TextEncoder();
	for (let nonce = start, i = 0; i < attempts; nonce += step, i++) {
		if (signal?.aborted) {
			return undefined;
		}
		const view = new DataView(await crypto.subtle.digest(algorithm, encoder.encode(challenge + nonce)));
		let bits = 0;
		for (let offset = 0; offset < view.byteLength; offset += 4) {
			const word = view.getUint32(offset);
			bits += Math.clz32(word);
			if (word !== 0 || bits >= difficulty) {
				break;
			}
		}
		if (bits >= difficulty) {
			return nonce;
		}
	}
	return undefined;
}

/**
 * Tells whether a nonce solves a challenge.
 * @param challenge The challenge of the prompt.
 * @param difficulty The number of leading zero bits that the digest must have.
 * @param nonce The nonce that {@link work} found.
 * @param algorithm The digest of the proof.
 * @returns `true` when the digest of `challenge + nonce` has at least `difficulty` leading zero bits.
 */
export async function verify(challenge: string, difficulty: number, nonce: number, algorithm: PowAlgorithm = "SHA-256"): Promise<boolean> {
	return (await search(challenge, difficulty, algorithm, nonce, 1, 1)) === nonce;
}

/**
 * Finds a nonce that solves a challenge. The client calls this function with the options of a prompt of the type
 * `pow`, and submits the nonce as the value.
 *
 * Without `options.threads`, the search runs on the current thread. With `options.threads`, the search runs in that
 * number of Web Workers, and each worker tries a different part of the nonces. The `Worker` global and
 * `URL.createObjectURL` must exist, as in a browser.
 *
 * @param challenge The challenge of the prompt.
 * @param difficulty The number of leading zero bits that the digest must have.
 * @param options The digest of the proof (default `"SHA-256"`), the number of Web Workers, and a signal that stops the
 * search.
 * @returns The first nonce that a worker finds. Two calls with the same challenge can return different nonces.
 * @throws {@link WorkAbortedError} When `options.signal` aborts the search.
 *
 * @example
 * ```ts
 * const { challenge, difficulty, algorithm } = prompt.options as PowPromptOptions;
 * const nonce = await work(challenge, difficulty, { algorithm, threads: navigator.hardwareConcurrency });
 * ```
 */
export async function work(
	challenge: string,
	difficulty: number,
	options?: { algorithm?: PowAlgorithm; threads?: number; signal?: AbortSignal },
): Promise<number> {
	const algorithm = options?.algorithm ?? "SHA-256";
	const signal = options?.signal;
	if (options?.threads === undefined) {
		const nonce = await search(challenge, difficulty, algorithm, 0, 1, Number.POSITIVE_INFINITY, signal);
		if (nonce === undefined) {
			throw new WorkAbortedError();
		}
		return nonce;
	}
	if (signal?.aborted) {
		throw new WorkAbortedError();
	}

	const threads = Math.max(1, Math.floor(options.threads));
	// The worker gets the search function as an argument, so the body reads no module-level name.
	const glue = (find: typeof search) => {
		addEventListener("message", async (event) => {
			const { challenge, difficulty, algorithm, start, step } = (event as MessageEvent).data;
			try {
				postMessage({ nonce: await find(challenge, difficulty, algorithm, start, step, Number.POSITIVE_INFINITY) });
			} catch (error) {
				postMessage({ error: String(error) });
			}
		});
	};
	const url = URL.createObjectURL(new Blob([`(${glue.toString()})(${search.toString()})`], { type: "text/javascript" }));
	const workers: Worker[] = [];
	const result = Promise.withResolvers<number>();
	const stop = () => {
		for (const worker of workers) {
			worker.terminate();
		}
		URL.revokeObjectURL(url);
		signal?.removeEventListener("abort", onAbort);
	};
	const onAbort = () => {
		stop();
		result.reject(new WorkAbortedError());
	};
	signal?.addEventListener("abort", onAbort);
	for (let i = 0; i < threads; i++) {
		const worker = new Worker(url);
		worker.addEventListener("message", (event) => {
			const data = (event as MessageEvent<{ nonce?: number; error?: string }>).data;
			stop();
			if (typeof data.nonce === "number") {
				result.resolve(data.nonce);
			} else {
				result.reject(new Error(data.error ?? "proof-of-work worker failed"));
			}
		});
		worker.addEventListener("error", (event) => {
			stop();
			result.reject(new Error(event.message || "proof-of-work worker failed"));
		});
		worker.postMessage({ challenge, difficulty, algorithm, start: i, step: threads });
		workers.push(worker);
	}
	return result.promise;
}

// What `getPrompt` keeps under `pow/<stateId>/<name>`. The record holds the difficulty and the digest, so a change of
// the options does not change a challenge that a client already works on.
type PendingChallenge = PowPromptOptions;

/**
 * A proof of work. The client must find a nonce for which the digest of `challenge + nonce` has a number of leading
 * zero bits. The work costs the client time, and the check costs the server one digest. The step slows down a bot
 * that sends many sign-ups or many sign-in attempts.
 *
 * The prompt has the type `pow`, and its `options` is a {@link PowPromptOptions}. The client calls {@link work} with
 * these options, and submits the nonce as a number. `getPrompt` writes a random challenge to KV under
 * `pow/<stateId>/<name>`, and gives the same challenge back while the challenge stays valid. The step accepts a
 * nonce one time only: it deletes the key when it checks a nonce, also when the nonce is wrong. After a wrong nonce,
 * the client gets a new challenge from the next prompt.
 *
 * The step proves nothing about the owner, so `proves` is `false`, and the step resolves no identity. In a sign-in,
 * put the step after an identification, for example `sequence("email", "pow", "password")`. A sign-up can put it
 * first.
 *
 * The record is a challenge with no data. It keeps no secret.
 *
 * @example
 * ```ts
 * new PowAuthDanceComponent({ difficulty: 18 });
 * ```
 */
export class PowAuthDanceComponent implements AuthDanceComponent {
	/** The record kind the component contributes to an identity. A proof of work never resolves an identity. */
	readonly kind: AuthDanceIdentityComponent["kind"] = "challenge";
	/** A nonce has no value to prove control of, so the class declares no `verificationComponent`. */
	readonly verifiable = false;
	/** Any client can do the work, so an accepted nonce proves nothing about the owner. */
	readonly proves = false;
	#difficulty: number;
	#algorithm: PowAlgorithm;
	#ttl: number;

	/**
	 * @param options The difficulty, the digest and the time to live of a challenge.
	 * @throws {TypeError} When `difficulty` is not an integer from 1 to the length of the digest in bits, or `ttl` is
	 * not a positive number.
	 */
	constructor(options: PowAuthDanceComponentOptions = {}) {
		this.#algorithm = options.algorithm ?? "SHA-256";
		this.#difficulty = options.difficulty ?? 16;
		this.#ttl = options.ttl ?? 300;
		const bits = { "SHA-1": 160, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512 }[this.#algorithm];
		if (bits === undefined) {
			throw new TypeError(`unknown proof-of-work algorithm ${this.#algorithm}`);
		}
		if (!Number.isInteger(this.#difficulty) || this.#difficulty < 1 || this.#difficulty > bits) {
			throw new TypeError(`difficulty must be an integer from 1 to ${bits}`);
		}
		if (!(this.#ttl > 0)) {
			throw new TypeError("ttl must be a positive number of seconds");
		}
	}

	/**
	 * Describes the input that the client renders. The input is not sendable.
	 *
	 * The first call of a dance step writes a new challenge to KV. A later call in the time to live gives back the same
	 * challenge, so the prompts of a choice and a new render of the step do not cancel the work of the client.
	 * @returns One input of the type `pow`, whose `options` is a {@link PowPromptOptions}.
	 */
	async getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput> {
		let pending = await this.#pending(context);
		if (!pending) {
			const bytes = crypto.getRandomValues(new Uint8Array(16));
			pending = {
				challenge: Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(""),
				difficulty: this.#difficulty,
				algorithm: this.#algorithm,
			};
			await context.storage.setKv(this.#key(context), JSON.stringify(pending), this.#ttl);
		}
		return {
			kind: "input",
			name: context.name,
			type: "pow",
			sendable: false,
			options: { ...pending },
		};
	}

	/**
	 * Builds the challenge record of a sign-up, an enroll, a rotate or a recover. A sign-up calls no `verifyPrompt`, so
	 * this method checks the nonce itself.
	 * @param component The component name that the record carries.
	 * @param value The nonce that the owner submitted.
	 * @param confirmed Whether the record starts as confirmed.
	 * @returns One challenge record with no data.
	 * @throws {InvalidPromptValueError} When the nonce does not solve the challenge, or no challenge is valid.
	 */
	async getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]> {
		if (!(await this.#consume(value, context))) {
			throw new InvalidPromptValueError("proof-of-work nonce does not solve the challenge");
		}
		return [{ kind: "challenge", component, confirmed }];
	}

	/**
	 * Checks the nonce against the challenge in KV, then deletes the key.
	 * @param value The nonce that the owner submitted.
	 * @returns `true` when the nonce solves the challenge. `false` for a wrong nonce, for a value that is not a
	 * non-negative safe integer, and when no challenge is valid. This method never returns an identity id.
	 */
	async verifyPrompt(value: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]> {
		return this.#consume(value, context);
	}

	// Reads the challenge, deletes it, and checks the nonce. The delete comes before the check, so one challenge gets one
	// answer only.
	async #consume(value: unknown, context: AuthDanceComponentContext): Promise<boolean> {
		const pending = await this.#pending(context);
		if (!pending) {
			return false;
		}
		await context.storage.unsetKv(this.#key(context));
		if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
			return false;
		}
		return verify(pending.challenge, pending.difficulty, value, pending.algorithm);
	}

	// The key of the challenge for this dance and this step.
	#key(context: AuthDanceComponentContext): string {
		return `pow/${context.stateId}/${context.name}`;
	}

	// The challenge that `getPrompt` wrote for this dance and this step. Returns `null` once the time to live passes,
	// and for a value in another shape.
	async #pending(context: AuthDanceComponentContext): Promise<PendingChallenge | null> {
		const raw = await context.storage.getKv(this.#key(context));
		if (!raw) {
			return null;
		}
		try {
			const parsed = JSON.parse(raw);
			return typeof parsed?.challenge === "string" &&
				typeof parsed.difficulty === "number" &&
				["SHA-1", "SHA-256", "SHA-384", "SHA-512"].includes(parsed.algorithm)
				? { challenge: parsed.challenge, difficulty: parsed.difficulty, algorithm: parsed.algorithm }
				: null;
		} catch {
			return null;
		}
	}
}
