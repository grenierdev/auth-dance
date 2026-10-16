import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "./identity.ts";
import type { AuthDanceMessage } from "./message.ts";
import type { AuthDancePromptInput } from "./prompt.ts";
import type { AuthDanceStorage } from "./storage.ts";

/** What the library gives a component on every call. A component keeps no dance state between calls. */
export interface AuthDanceComponentContext {
	/** The store the component reads and writes through. A component keeps its own records in the key-value part. */
	storage: AuthDanceStorage;
	/**
	 * The id of the dance in progress. A component that keeps a value between two calls keys the record on this id.
	 *
	 * The client can replay an earlier state, and the replay keeps this id. A replay can resolve another identity or
	 * collect another value. Keep the identity or the recipient in the record, and compare them when you read it back.
	 */
	stateId: string;
	/**
	 * The name of the step in progress.
	 *
	 * A verification component reads the name of the component it proves. A `subscribe` puts the name of the channel here.
	 */
	name: string;
	/** Which flow runs this step: `sign-in`, `sign-up`, `enroll`, `rotate`, `recover` or `subscribe`. */
	flow: string;
	/**
	 * The identity as it stands, when the library holds one.
	 *
	 * The library omits it on the first step of a sign-in and of a recovery. It also omits it from every prompt it
	 * builds from the choreography or from a recovery choreography, so `getPrompt` in a sign-in, a sign-up or a step
	 * of a recovery dance never reads one. In a `recover` flow, a prompt with an identity collects the replacement.
	 */
	identity?: AuthDanceIdentity;
}

/**
 * One step of the dance. A component builds its prompt, checks what the owner submits, and says what the value
 * becomes on an identity.
 */
export interface AuthDanceComponent {
	/**
	 * What the component contributes to an identity. An `identification` resolves an identity on its own. A
	 * `challenge` only proves a claim against an identity. A component never declares `channel`.
	 */
	kind: AuthDanceIdentityComponent["kind"];
	/**
	 * Whether the component can prove control of its own value.
	 *
	 * A component that sets this to `true` must also declare `verificationComponent`. Without that method a recovery
	 * raises `ComponentNotVerifiableError` on the first submit.
	 *
	 * A recovery runs the verification of a non-proving identification that carries this flag, after `verifyPrompt`
	 * resolves the identity. The step counts as proof only once that verification succeeds. The one-time code to an
	 * address is an example.
	 */
	verifiable: boolean;
	/**
	 * Whether a value that `verifyPrompt` accepts proves that the owner holds the factor, and does not only name an
	 * identity. When you omit it, a `challenge` proves and an `identification` does not.
	 *
	 * Every complete path of the choreography needs one step that proves. A third-party identification that checks a
	 * secret, a signature for example, sets this to `true`.
	 */
	proves?: boolean;
	/** Builds the prompt the client renders for this step. */
	getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput>;
	/**
	 * Delivers the prompt over a channel. Return the message, and the library delivers it over the channel the
	 * recipient names.
	 *
	 * The library raises `ComponentNotSendableError` for a component without this method, and for a component that
	 * returns nothing.
	 *
	 * @param locale The language of the message content.
	 */
	sendPrompt?(locale: string, context: AuthDanceComponentContext): Promise<AuthDanceMessage>;
	/**
	 * Converts a submitted value into the records the identity holds. One component can return more than one record.
	 *
	 * @param component The name to store the record under. The choreography uses the same name.
	 * @param value What the owner submitted.
	 * @param confirmed Whether control of `value` is already proven. The library always passes `false`. It confirms
	 * the record itself, at once for a component with no verification, and otherwise after the validation succeeds.
	 */
	getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]>;
	/**
	 * Returns the component that proves control of the value this component collected.
	 *
	 * A `verifiable` component declares this method. Without it the library confirms a collected value at once, and a
	 * flow that needs proof raises `ComponentNotVerifiableError`.
	 *
	 * The library never registers the component this method returns. That component gets the same context as the
	 * parent, so `context.name` still names the parent step.
	 */
	verificationComponent?(context: AuthDanceComponentContext): Promise<AuthDanceComponent>;
	/**
	 * Checks a submitted value against the identity the dance has resolved so far.
	 *
	 * When a component answers `true` and the dance has resolved nobody, the library raises
	 * `IdentityNotResolvedError`. When the id contradicts an id an earlier step resolved, it raises
	 * `IdentityMismatchError`. Any other answer raises `InvalidPromptValueError`, and so does an id that names no
	 * stored identity.
	 *
	 * A recovery needs an identity id from the first submit. Any other answer raises `IdentityNotResolvedError`.
	 *
	 * On a verification component the library accepts `true` alone. Any other answer raises
	 * `InvalidValidationValueError`.
	 *
	 * @returns `true` to accept the value without resolving anyone. An identity id to accept it and say who it is.
	 * Any other answer, `false` and `undefined` included, rejects the value.
	 */
	verifyPrompt(value: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]>;
	/**
	 * Rewrites the records of an identity after a sign-in step accepts `value`. A component that stores a hash
	 * declares this method to move an old record to its current parameters.
	 *
	 * The library replaces the records of the same name with what this method returns, and saves the identity before
	 * it mints tokens. No identity hook fires, because the identity holds the same factors.
	 *
	 * @param value The value that `verifyPrompt` accepted.
	 * @param context The context of the step. `context.identity` is the identity the step resolved.
	 * @returns The replacement records, or nothing to keep the stored records.
	 */
	upgradeIdentityComponent?(value: unknown, context: AuthDanceComponentContext): Promise<AuthDanceIdentityComponent[] | undefined>;
}
