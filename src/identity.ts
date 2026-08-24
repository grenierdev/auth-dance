import * as v from "valibot";

// The private `data` bag, declared one time. Each stored schema spreads it over its public half.
const AuthDanceIdentityDataField = { data: v.optional(v.record(v.string(), v.unknown())) };

/**
 * An identification enrolled on an identity, as a client may see it. It resolves an identity on its own, so
 * `AuthDanceIdentityProvider.getByIdentification` finds the owner from `component` plus `identification`.
 */
export interface AuthDanceIdentityIdentificationPublic {
	/** Tags the record as an identification. */
	kind: "identification";
	/** Name of the component that produced the record. The choreography and `/enroll` use the same name. */
	component: string;
	/** The value that names the owner, for example the address `EmailAuthDanceComponent` collected. */
	identification: string;
	/**
	 * Whether the owner has proven control of `identification`. `EmailAuthDanceComponent` refuses an unconfirmed
	 * record. The lock-out check counts only confirmed components.
	 */
	confirmed: boolean;
	/**
	 * Names of the components that depend on this identification, each an identification or a challenge, never
	 * a channel. Removal applies both ways: with this record, and with any component named here.
	 */
	linkedTo?: string[];
}

/** An identification as the identity store holds it, with the private `data` bag. */
export interface AuthDanceIdentityIdentification extends AuthDanceIdentityIdentificationPublic {
	/** The private bag this component owns. No component of this library writes to it. `/list-components` drops it. */
	data?: Record<string, unknown>;
}

const AuthDanceIdentityIdentificationFields = {
	kind: v.literal("identification"),
	component: v.string(),
	identification: v.string(),
	confirmed: v.boolean(),
	linkedTo: v.optional(v.array(v.string())),
} as const;

/** Parses a stored identification record, the private `data` bag included. */
export const AuthDanceIdentityIdentification: v.GenericSchema<AuthDanceIdentityIdentification> = v.pipe(
	v.object({ ...AuthDanceIdentityIdentificationFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityIdentification"),
	v.description(
		"An identity identification object that contains an identity id, component, identification, confirmation status, associated data, and the names of the components that depend on it.",
	),
);

/** Parses an identification without its private `data` bag. */
export const AuthDanceIdentityIdentificationPublic: v.GenericSchema<AuthDanceIdentityIdentificationPublic> = v.pipe(
	v.object(AuthDanceIdentityIdentificationFields),
	v.title("IdentityIdentificationPublic"),
	v.description(
		"An identity identification as disclosed to a client: its component, identification, confirmation status, and the components that depend on it.",
	),
);

/**
 * A challenge enrolled on an identity, as a client may see it. A challenge proves a claim against an identity
 * another component resolved. It carries no value that resolves an owner.
 */
export interface AuthDanceIdentityChallengePublic {
	/** Tags the record as a challenge. */
	kind: "challenge";
	/** Name of the component that produced the record. The choreography and `/enroll` use the same name. */
	component: string;
	/** Whether the owner has proven control of the secret. The sign-up path and the lock-out check count only confirmed components. */
	confirmed: boolean;
	/**
	 * Names of the components that depend on this challenge, each an identification or a challenge, never a
	 * channel. `EmailAuthDanceComponent` names its own identification here. Removal applies both ways.
	 */
	linkedTo?: string[];
}

/** A challenge as the identity store holds it, with the private `data` bag. */
export interface AuthDanceIdentityChallenge extends AuthDanceIdentityChallengePublic {
	/**
	 * The private bag this component owns. `PasswordAuthDanceComponent` writes the password hash to `data.hash`.
	 * `OtpAuthDanceComponent` writes the recipient to `data.recipient` and keeps the code in KV under
	 * `otp/<stateId>/<name>`.
	 */
	data?: Record<string, unknown>;
}

const AuthDanceIdentityChallengeFields = {
	kind: v.literal("challenge"),
	component: v.string(),
	confirmed: v.boolean(),
	linkedTo: v.optional(v.array(v.string())),
} as const;

/** Parses a stored challenge record, the private `data` bag included. */
export const AuthDanceIdentityChallenge: v.GenericSchema<AuthDanceIdentityChallenge> = v.pipe(
	v.object({ ...AuthDanceIdentityChallengeFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityChallenge"),
	v.description(
		"An identity challenge object that contains an identity id, component, confirmation status, associated data, and the names of the components that depend on it.",
	),
);

/** Parses a challenge without its private `data` bag, so the secret stays out of the parsed value. */
export const AuthDanceIdentityChallengePublic: v.GenericSchema<AuthDanceIdentityChallengePublic> = v.pipe(
	v.object(AuthDanceIdentityChallengeFields),
	v.title("IdentityChallengePublic"),
	v.description(
		"An identity challenge as disclosed to a client: its component, confirmation status, and the components that depend on it — never the secret it verifies.",
	),
);

/**
 * A channel subscribed on an identity, as a client may see it. A channel is where the library delivers a
 * message, such as a one-time code. The recipient stays in the private `data` bag.
 */
export interface AuthDanceIdentityChannelPublic {
	/** Tags the record as a channel. */
	kind: "channel";
	/** Name of the channel, the same key `api.channels` maps to a delivery adapter. One record per name, so a re-emit replaces it. */
	component: string;
	/**
	 * Whether the owner has proven control of the recipient. The subscribe flow sets it to `true` after the
	 * one-time code verifies, and it delivers that code over an already confirmed channel.
	 * `EmailAuthDanceComponent` emits its channel with `confirmed: true` at collection time.
	 */
	confirmed: boolean;
	/**
	 * Names of the components that depend on this channel, each an identification or a challenge, never a
	 * channel. `EmailAuthDanceComponent` names its identification here. Removal applies both ways.
	 */
	linkedTo?: string[];
}

/** A channel as the identity store holds it, with the private `data` bag. */
export interface AuthDanceIdentityChannel extends AuthDanceIdentityChannelPublic {
	/**
	 * The recipient of every message over this channel. `EmailAuthDanceComponent` writes the address under
	 * `email`. The subscribe flow writes the recipient under the channel name.
	 */
	data?: Record<string, unknown>;
}

const AuthDanceIdentityChannelFields = {
	kind: v.literal("channel"),
	component: v.string(),
	confirmed: v.boolean(),
	linkedTo: v.optional(v.array(v.string())),
} as const;

/** Parses a stored channel record, the recipient in the private `data` bag included. */
export const AuthDanceIdentityChannel: v.GenericSchema<AuthDanceIdentityChannel> = v.pipe(
	v.object({ ...AuthDanceIdentityChannelFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityChannel"),
	v.description(
		"An identity channel object that contains an identity id, channel, confirmation status, associated data, and the names of the components that depend on it.",
	),
);

/** Parses a channel without its private `data` bag, so the recipient stays out of the parsed value. */
export const AuthDanceIdentityChannelPublic: v.GenericSchema<AuthDanceIdentityChannelPublic> = v.pipe(
	v.object(AuthDanceIdentityChannelFields),
	v.title("IdentityChannelPublic"),
	v.description(
		"An identity channel as disclosed to a client: its channel, confirmation status, and the components that depend on it — never the recipient itself.",
	),
);

/**
 * One step recorded on an identity: an identification, a challenge, or a channel. The `kind` field picks the
 * member. `getIdentityComponent` returns an array, so one step can record more than one.
 */
export type AuthDanceIdentityComponent = AuthDanceIdentityIdentification | AuthDanceIdentityChallenge | AuthDanceIdentityChannel;

/** Parses one stored component record of any kind. */
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

/** One step recorded on an identity, without the private `data` bag. */
export type AuthDanceIdentityComponentPublic =
	| AuthDanceIdentityIdentificationPublic
	| AuthDanceIdentityChallengePublic
	| AuthDanceIdentityChannelPublic;

/** Parses one component as a client may see it. The `/list-components` body holds an array of it. */
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
	 * Free-form data about the owner, such as a display name. The library reads the keys as the scopes of a new
	 * session, then copies each key that session holds into the protected header of the `id_token`.
	 */
	data?: Record<string, unknown>;
	/**
	 * Every component enrolled on the identity. The lock-out check refuses an unenroll when the confirmed
	 * entries that remain cover no complete path through the choreography.
	 */
	components: AuthDanceIdentityComponent[];
}

/** Parses a whole identity record as an `AuthDanceIdentityProvider` stores it, the private `data` bags included. */
export const AuthDanceIdentity: v.GenericSchema<AuthDanceIdentity> = v.pipe(
	v.object({
		id: v.string(),
		data: v.optional(v.record(v.string(), v.unknown())),
		components: v.array(AuthDanceIdentityComponent),
	}),
	v.title("Identity"),
	v.description("An identity object that contains an id and associated data."),
);
