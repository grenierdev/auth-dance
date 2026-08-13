import * as v from "valibot";

// Every component record splits in two: what the identity store holds, and what a client may see. The
// difference is the private `data` bag that each component owns. PasswordAuthDanceComponent keeps the
// password hash there, and OtpAuthDanceComponent keeps the value the owner submitted. So the `…Public` half
// of each pair is the stored shape without that one field, and the stored shape extends the public half.
// This const declares that one field one time, and each stored schema spreads it.
const AuthDanceIdentityDataField = { data: v.optional(v.record(v.string(), v.unknown())) };

/**
 * An identification enrolled on an identity, as a client may see it.
 *
 * An identification resolves an identity on its own, so `AuthDanceIdentityProvider.getByIdentification`
 * finds the owner from `component` plus `identification`. The `/list-components` route returns this shape.
 */
export interface AuthDanceIdentityIdentificationPublic {
	/** Tags the record as an identification, so the library selects it when it resolves the owner. */
	kind: "identification";
	/** Name of the component that produced the record. The choreography and `/enroll` use the same name. */
	component: string;
	/** The value that names the owner, for example the address `EmailAuthDanceComponent` collected. */
	identification: string;
	/**
	 * Whether the owner has proven control of `identification`.
	 *
	 * `submitValidation` sets it to `true` after the verification component accepts the value. When a component
	 * offers no verification of its own, `submitPrompt` sets it as soon as the owner submits the value.
	 * `EmailAuthDanceComponent` refuses to resolve an identity from an unconfirmed record, and the lock-out
	 * check counts only confirmed components.
	 */
	confirmed: boolean;
	/**
	 * Names of the components that depend on this identification. Every name is an identification or a challenge,
	 * never a channel: a channel serves the components that name it and depends on none of them.
	 *
	 * `unenroll` and `unsubscribe` read the list both ways. Removing this record removes every component named
	 * here, and removing any of them removes this record, so a removal never leaves half of what one component
	 * contributed behind.
	 */
	linkedTo?: string[];
}

/** An identification as the identity store holds it: the disclosed shape plus the private `data` bag. */
export interface AuthDanceIdentityIdentification extends AuthDanceIdentityIdentificationPublic {
	/**
	 * The private `data` bag this component owns on the record. `EmailAuthDanceComponent` leaves it unset and
	 * writes the address to the channel record it emits beside this one. No component of this library writes to
	 * it. The `/list-components` route drops this field, so no client sees it.
	 */
	data?: Record<string, unknown>;
}

const AuthDanceIdentityIdentificationFields = {
	kind: v.literal("identification"),
	component: v.string(),
	identification: v.string(),
	confirmed: v.boolean(),
	linkedTo: v.optional(v.array(v.string())),
} as const;

/**
 * Parses a stored identification record, the private `data` bag included. The `AuthDanceIdentityComponent`
 * union composes it, and the flow states in `state.ts` parse the collected components through that union.
 */
export const AuthDanceIdentityIdentification: v.GenericSchema<AuthDanceIdentityIdentification> = v.pipe(
	v.object({ ...AuthDanceIdentityIdentificationFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityIdentification"),
	v.description(
		"An identity identification object that contains an identity id, component, identification, confirmation status, associated data, and the names of the components that depend on it.",
	),
);

/**
 * Parses an identification without its private `data` bag. The `AuthDanceIdentityComponentPublic` union composes
 * it, and that union describes the `/list-components` body in the generated OpenAPI document.
 */
export const AuthDanceIdentityIdentificationPublic: v.GenericSchema<AuthDanceIdentityIdentificationPublic> = v.pipe(
	v.object(AuthDanceIdentityIdentificationFields),
	v.title("IdentityIdentificationPublic"),
	v.description(
		"An identity identification as disclosed to a client: its component, identification, confirmation status, and the components that depend on it.",
	),
);

/**
 * A challenge enrolled on an identity, as a client may see it.
 *
 * A challenge only proves a claim against an identity another component resolved. It therefore carries no
 * value that resolves an owner. The `/list-components` route returns this shape.
 */
export interface AuthDanceIdentityChallengePublic {
	/** Tags the record as a challenge, so the library selects it when it checks a submitted secret. */
	kind: "challenge";
	/** Name of the component that produced the record. The choreography and `/enroll` use the same name. */
	component: string;
	/**
	 * Whether the owner has proven control of the secret the challenge checks.
	 *
	 * A password offers no verification of its own, so `submitPrompt` confirms it as soon as the owner submits
	 * it. The sign-up path and the lock-out check count only confirmed components.
	 */
	confirmed: boolean;
	/**
	 * Names of the components that depend on this challenge. Every name is an identification or a challenge,
	 * never a channel: a challenge reaches its owner through a channel, and the channel names the challenge
	 * rather than the other way round.
	 *
	 * `EmailAuthDanceComponent` names its own identification here, on the one-time code challenge it contributes.
	 * `unenroll` and `unsubscribe` read the list both ways, the way they read the list a channel carries.
	 */
	linkedTo?: string[];
}

/** A challenge as the identity store holds it: the disclosed shape plus the private `data` bag. */
export interface AuthDanceIdentityChallenge extends AuthDanceIdentityChallengePublic {
	/**
	 * The private `data` bag this component owns on the record. `PasswordAuthDanceComponent` writes the password
	 * hash to `data.hash`, and it verifies each submission against that string. `OtpAuthDanceComponent`
	 * writes the submitted value to `data.recipient`, and it keeps the code itself in KV under
	 * `otp/<stateId>/<name>`. The `/list-components` route drops this field, so no client sees it.
	 */
	data?: Record<string, unknown>;
}

const AuthDanceIdentityChallengeFields = {
	kind: v.literal("challenge"),
	component: v.string(),
	confirmed: v.boolean(),
	linkedTo: v.optional(v.array(v.string())),
} as const;

/**
 * Parses a stored challenge record, the private `data` bag included. The `AuthDanceIdentityComponent` union
 * composes it, and the flow states in `state.ts` parse the collected components through that union.
 */
export const AuthDanceIdentityChallenge: v.GenericSchema<AuthDanceIdentityChallenge> = v.pipe(
	v.object({ ...AuthDanceIdentityChallengeFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityChallenge"),
	v.description(
		"An identity challenge object that contains an identity id, component, confirmation status, associated data, and the names of the components that depend on it.",
	),
);

/**
 * Parses a challenge without its private `data` bag, so the secret it verifies stays out of the parsed value. The
 * `AuthDanceIdentityComponentPublic` union composes it for the `/list-components` body.
 */
export const AuthDanceIdentityChallengePublic: v.GenericSchema<AuthDanceIdentityChallengePublic> = v.pipe(
	v.object(AuthDanceIdentityChallengeFields),
	v.title("IdentityChallengePublic"),
	v.description(
		"An identity challenge as disclosed to a client: its component, confirmation status, and the components that depend on it — never the secret it verifies.",
	),
);

/**
 * A channel subscribed on an identity, as a client may see it.
 *
 * A channel is where the library delivers a message, such as the one-time code that confirms another
 * component. The recipient stays in the private `data` bag, so this shape names the channel and never the
 * address behind it. The `/list-components` route returns it.
 */
export interface AuthDanceIdentityChannelPublic {
	/** Tags the record as a channel, so the library selects it when it searches for a delivery target. */
	kind: "channel";
	/**
	 * Name of the channel, the same key `api.channels` maps to a delivery adapter. An identity holds one
	 * record per name, so a channel a component emits again replaces the record of that name.
	 */
	component: string;
	/**
	 * Whether the owner has proven control of the recipient. The subscribe flow sets it to `true` after the
	 * one-time code verifies. The library delivers that code over an already confirmed channel, never over
	 * this one. `EmailAuthDanceComponent` is the exception. It emits its channel with `confirmed: true` at
	 * collection time, because the identification beside it carries the same address.
	 */
	confirmed: boolean;
	/**
	 * Names of the components that depend on this channel. Every name is an identification or a challenge, never
	 * a channel. `EmailAuthDanceComponent` names its identification here on the channel it contributes.
	 *
	 * `unenroll` and `unsubscribe` read the list both ways: removing this channel removes every component named
	 * here, because a component a channel carries has no way to reach its owner once the channel is gone, and
	 * removing one of those components removes the channel it left behind.
	 */
	linkedTo?: string[];
}

/** A channel as the identity store holds it: the disclosed shape plus the private `data` bag. */
export interface AuthDanceIdentityChannel extends AuthDanceIdentityChannelPublic {
	/**
	 * The recipient of every message over this channel, such as an address or a phone number.
	 * `EmailAuthDanceComponent` writes the address under `email`, and the subscribe flow writes the submitted
	 * recipient under the channel name. The `/list-components` route drops this field, so no client sees it.
	 */
	data?: Record<string, unknown>;
}

const AuthDanceIdentityChannelFields = {
	kind: v.literal("channel"),
	component: v.string(),
	confirmed: v.boolean(),
	linkedTo: v.optional(v.array(v.string())),
} as const;

/**
 * Parses a stored channel record, the recipient in the private `data` bag included. `AuthDanceMessage` in
 * `message.ts` uses this shape as the recipient of a message, and `AuthDanceStateSubscribe` carries the
 * pending channel in it.
 */
export const AuthDanceIdentityChannel: v.GenericSchema<AuthDanceIdentityChannel> = v.pipe(
	v.object({ ...AuthDanceIdentityChannelFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityChannel"),
	v.description(
		"An identity channel object that contains an identity id, channel, confirmation status, associated data, and the names of the components that depend on it.",
	),
);

/**
 * Parses a channel without its private `data` bag, so the recipient stays out of the parsed value. The
 * `AuthDanceIdentityComponentPublic` union composes it for the `/list-components` body.
 */
export const AuthDanceIdentityChannelPublic: v.GenericSchema<AuthDanceIdentityChannelPublic> = v.pipe(
	v.object(AuthDanceIdentityChannelFields),
	v.title("IdentityChannelPublic"),
	v.description(
		"An identity channel as disclosed to a client: its channel, confirmation status, and the components that depend on it — never the recipient itself.",
	),
);

/**
 * One step recorded on an identity: an identification, a challenge, or a channel. The `kind` field picks the
 * member. `getIdentityComponent` returns an array of these records, so one step may record more than one.
 * `EmailAuthDanceComponent` returns three: an identification, the channel that reaches the same address, and the
 * one-time code challenge that the library delivers over that channel.
 */
export type AuthDanceIdentityComponent = AuthDanceIdentityIdentification | AuthDanceIdentityChallenge | AuthDanceIdentityChannel;

/**
 * Parses one stored component record of any kind. `AuthDanceIdentity` uses it for the list an identity holds.
 * The flow states in `state.ts` use it for the components a flow collects before the library persists them.
 */
export const AuthDanceIdentityComponent: v.GenericSchema<AuthDanceIdentityComponent> = v.pipe(
	v.union([
		AuthDanceIdentityIdentification,
		AuthDanceIdentityChallenge,
		AuthDanceIdentityChannel,
	]),
	v.title("IdentityComponent"),
	v.description(
		"An identity component object that can be either an identity identification, an identity challenge, or an identity channel.",
	),
);

/**
 * One step recorded on an identity, without the private `data` bag. `app.ts` drops the whole `data` field
 * rather than filtering it, because no component declares which of its keys are safe to disclose.
 */
export type AuthDanceIdentityComponentPublic =
	| AuthDanceIdentityIdentificationPublic
	| AuthDanceIdentityChallengePublic
	| AuthDanceIdentityChannelPublic;

/**
 * Parses one component as a client may see it. `AuthDanceResponseComponents` in `response.ts` puts an array
 * of it in the `/list-components` body, so the route and its documented schema describe one shape.
 */
export const AuthDanceIdentityComponentPublic: v.GenericSchema<AuthDanceIdentityComponentPublic> = v.pipe(
	v.union([
		AuthDanceIdentityIdentificationPublic,
		AuthDanceIdentityChallengePublic,
		AuthDanceIdentityChannelPublic,
	]),
	v.title("IdentityComponentPublic"),
	v.description(
		"An identity component as disclosed to a client — an identification, a challenge or a channel — without the component's private data.",
	),
);

/** Who the dance resolves to: the id of the owner, free-form data about the owner, and the enrolled steps. */
export interface AuthDanceIdentity {
	/** The identity id, a ksuid with an `id_` prefix. `AuthDanceStorage.createIdentity` mints it. */
	id: string;
	/**
	 * Free-form data about the owner, such as a display name. The library reads the keys as the scopes of a
	 * new session. It then copies each key that session holds into the protected header of the `id_token`.
	 */
	data?: Record<string, unknown>;
	/**
	 * Every component enrolled on the identity. A component reads this list from its context, which is how
	 * `PasswordAuthDanceComponent` finds the record it verifies a submission against. The lock-out check reads
	 * the list too. It refuses an unenroll when the confirmed entries that remain cover no complete path
	 * through the choreography.
	 */
	components: AuthDanceIdentityComponent[];
}

/**
 * Parses a whole identity record as an `AuthDanceIdentityProvider` stores it, the private `data` bags included.
 *
 * No code in this library parses with this schema. `mod.ts` exports it, so an identity provider can validate a
 * record it read from its own store.
 */
export const AuthDanceIdentity: v.GenericSchema<AuthDanceIdentity> = v.pipe(
	v.object({
		id: v.string(),
		data: v.optional(v.record(v.string(), v.unknown())),
		components: v.array(AuthDanceIdentityComponent),
	}),
	v.title("Identity"),
	v.description("An identity object that contains an id and associated data."),
);
