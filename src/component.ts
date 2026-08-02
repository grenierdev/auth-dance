import type { AuthDanceIdentity, AuthDanceIdentityComponent } from "./identity.ts";
import type { AuthDanceMessage } from "./message.ts";
import type { AuthDancePromptInput } from "./prompt.ts";
import type { AuthDanceStorage } from "./storage.ts";

/**
 * What the library hands a component on every call. A component keeps no dance state between calls, so one step
 * reads everything it needs from here.
 */
export interface AuthDanceComponentContext {
	/**
	 * The store the component reads and writes through. A component keeps its own records in the key-value part,
	 * a pending one-time code for example. `EmailAuthDanceComponent` also resolves an identity through this store.
	 */
	storage: AuthDanceStorage;
	/**
	 * The id of the dance in progress. A component that must keep a value between two calls keys the record on
	 * this id, the way the one-time code component keys `otp/<stateId>/<name>`.
	 */
	stateId: string;
	/**
	 * The name of the step in progress. The choreography names most steps, and the component puts the name in the
	 * prompt it builds and in the record it returns.
	 *
	 * A verification component reads the name of the component it proves, because its parent builds it and the
	 * library never registers it. A `subscribe` puts the name of the channel here instead.
	 */
	name: string;
	/**
	 * Which flow runs this step: `sign-in`, `sign-up`, `enroll`, `rotate`, `recover` or `subscribe`. A component
	 * can act one way during an enrollment and another way during an authentication.
	 */
	flow: string;
	/**
	 * The identity as it stands, when the library holds one. During a rotation the record the flow replaces is
	 * still on it. During a sign-up the components collected so far are on it.
	 *
	 * The library omits it on the first step of a sign-in and of a recovery, because no step has resolved an
	 * identity yet. It also omits it from every prompt it builds from the choreography, so `getPrompt` in a
	 * sign-in or a sign-up never reads one.
	 */
	identity?: AuthDanceIdentity;
}

/**
 * One step of the dance. A component builds its prompt, checks what the owner submits, and says what the value
 * becomes on an identity. The library drives the same methods in every flow, from a sign-in to a rotation.
 */
export interface AuthDanceComponent {
	/**
	 * What the component contributes to an identity. An `identification` resolves an identity on its own, an
	 * email address for example. A `challenge` only proves a claim against an identity, a password for example.
	 *
	 * The type also holds `channel`, but a component never declares it. A channel is a record a component emits
	 * beside its own record, not a step of the dance.
	 */
	kind: AuthDanceIdentityComponent["kind"];
	/**
	 * Whether the component can prove control of its own value. A component that identifies by an email address
	 * proves control with a code sent to that address. A password proves nothing when the owner types it again.
	 *
	 * A component that sets this to `true` must also declare `verificationComponent`. Without that method a
	 * recovery raises `ComponentNotVerifiableError` on the first submit.
	 *
	 * `recover` is the only flow that reads this flag. A recovery starts from one component alone. That component
	 * must resolve an identity, prove control of it, and be a first move of the choreography. `recover` raises
	 * `ComponentNotRecoverableError` for any other component.
	 */
	verifiable: boolean;
	/** Builds the prompt the client renders for this step. */
	getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput>;
	/**
	 * Delivers the prompt over a channel, a one-time code sent by mail for example. Return the message, and the
	 * library delivers it over the channel the recipient names.
	 *
	 * Only a sendable component declares this method. The library raises `ComponentNotSendableError` for a
	 * component without it, and for a component that returns nothing.
	 *
	 * @param locale The language of the message content.
	 */
	sendPrompt?(locale: string, context: AuthDanceComponentContext): Promise<AuthDanceMessage>;
	/**
	 * Converts a submitted value into the records the identity holds. One component can return more than one
	 * record. The email component returns its identification, plus the channel that reaches that address.
	 *
	 * `context.identity` is the identity as it stands, which lets the component refuse a value on grounds the
	 * value alone does not carry. During a rotation the record the flow replaces is still on the identity. During
	 * a sign-up the value collected a step earlier is on it.
	 *
	 * @param component The name to store the record under. The choreography uses the same name.
	 * @param value What the owner submitted.
	 * @param confirmed Whether control of `value` is already proven. The library always passes `false`. It
	 * confirms the record itself, at once for a component with no verification, and otherwise after the
	 * validation succeeds.
	 */
	getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]>;
	/**
	 * Returns the component that proves control of the value this component collected. The email component
	 * returns a one-time code component aimed at the address the flow enrolls.
	 *
	 * A `verifiable` component declares this method. Without it the library confirms a collected value at once,
	 * and a flow that needs proof raises `ComponentNotVerifiableError`.
	 *
	 * The library never registers the component this method returns. It hands that component the same context as
	 * the parent, so `context.name` still names the parent step.
	 */
	verificationComponent?(context: AuthDanceComponentContext): Promise<AuthDanceComponent>;
	/**
	 * Checks a submitted value against the identity the dance has resolved so far.
	 *
	 * A challenge on its own cannot name a signer. When a component answers `true` and the dance has resolved
	 * nobody, the library raises `IdentityNotResolvedError`. When the id contradicts an id an earlier step
	 * resolved, the library raises `IdentityMismatchError`. In a sign-in an answer of `false` raises
	 * `InvalidPromptValueError`.
	 *
	 * A recovery needs an identity id from the first submit. Any other answer raises `IdentityNotResolvedError`.
	 *
	 * The library calls this method on a verification component too, and there it accepts `true` alone. Any other
	 * answer raises `InvalidValidationValueError`.
	 *
	 * @returns `false` to reject the value. `true` to accept it without resolving anyone. An identity id to say
	 * who it is.
	 */
	verifyPrompt(value: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]>;
}
