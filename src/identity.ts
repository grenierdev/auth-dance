import * as v from "valibot";

// Every component splits in two: what the identity holds, and what a client may be told about it. The
// difference is `data`, the component's own private store — PasswordAuthDanceComponent keeps the hash there,
// OtpAuthDanceComponent its pending code — so the `…Public` half of each pair is the stored shape minus that
// one field, and the stored shape is declared by extending it. Sharing the field list this way is what
// keeps the two from drifting apart.
const AuthDanceIdentityDataField = { data: v.optional(v.record(v.string(), v.unknown())) };

export interface AuthDanceIdentityIdentificationPublic {
	kind: "identification";
	component: string;
	identification: string;
	confirmed: boolean;
}

export interface AuthDanceIdentityIdentification extends AuthDanceIdentityIdentificationPublic {
	data?: Record<string, unknown>;
}

const AuthDanceIdentityIdentificationFields = {
	kind: v.literal("identification"),
	component: v.string(),
	identification: v.string(),
	confirmed: v.boolean(),
} as const;

export const AuthDanceIdentityIdentification: v.GenericSchema<AuthDanceIdentityIdentification> = v.pipe(
	v.object({ ...AuthDanceIdentityIdentificationFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityIdentification"),
	v.description(
		"An identity identification object that contains an identity id, component, identification, confirmation status, and associated data.",
	),
);

export const AuthDanceIdentityIdentificationPublic: v.GenericSchema<AuthDanceIdentityIdentificationPublic> = v.pipe(
	v.object(AuthDanceIdentityIdentificationFields),
	v.title("IdentityIdentificationPublic"),
	v.description("An identity identification as disclosed to a client: its component, identification and confirmation status."),
);

export interface AuthDanceIdentityChallengePublic {
	kind: "challenge";
	component: string;
	confirmed: boolean;
}

export interface AuthDanceIdentityChallenge extends AuthDanceIdentityChallengePublic {
	data?: Record<string, unknown>;
}

const AuthDanceIdentityChallengeFields = {
	kind: v.literal("challenge"),
	component: v.string(),
	confirmed: v.boolean(),
} as const;

export const AuthDanceIdentityChallenge: v.GenericSchema<AuthDanceIdentityChallenge> = v.pipe(
	v.object({ ...AuthDanceIdentityChallengeFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityChallenge"),
	v.description(
		"An identity challenge object that contains an identity id, component, confirmation status, and associated data.",
	),
);

export const AuthDanceIdentityChallengePublic: v.GenericSchema<AuthDanceIdentityChallengePublic> = v.pipe(
	v.object(AuthDanceIdentityChallengeFields),
	v.title("IdentityChallengePublic"),
	v.description("An identity challenge as disclosed to a client: its component and confirmation status, never the secret it verifies."),
);

export interface AuthDanceIdentityChannelPublic {
	kind: "channel";
	channel: string;
	confirmed: boolean;
	linkedTo?: string[];
}

export interface AuthDanceIdentityChannel extends AuthDanceIdentityChannelPublic {
	data?: Record<string, unknown>;
}

const AuthDanceIdentityChannelFields = {
	kind: v.literal("channel"),
	channel: v.string(),
	confirmed: v.boolean(),
	linkedTo: v.optional(v.array(v.string())),
} as const;

export const AuthDanceIdentityChannel: v.GenericSchema<AuthDanceIdentityChannel> = v.pipe(
	v.object({ ...AuthDanceIdentityChannelFields, ...AuthDanceIdentityDataField }),
	v.title("IdentityChannel"),
	v.description(
		"An identity channel object that contains an identity id, channel, confirmation status, associated data, and the names of the components that depend on it.",
	),
);

export const AuthDanceIdentityChannelPublic: v.GenericSchema<AuthDanceIdentityChannelPublic> = v.pipe(
	v.object(AuthDanceIdentityChannelFields),
	v.title("IdentityChannelPublic"),
	v.description(
		"An identity channel as disclosed to a client: its channel, confirmation status, and the components that depend on it — never the recipient itself.",
	),
);

export type AuthDanceIdentityComponent = AuthDanceIdentityIdentification | AuthDanceIdentityChallenge | AuthDanceIdentityChannel;

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

export type AuthDanceIdentityComponentPublic =
	| AuthDanceIdentityIdentificationPublic
	| AuthDanceIdentityChallengePublic
	| AuthDanceIdentityChannelPublic;

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

export interface AuthDanceIdentity {
	id: string;
	data?: Record<string, unknown>;
	components: AuthDanceIdentityComponent[];
}

export const AuthDanceIdentity: v.GenericSchema<AuthDanceIdentity> = v.pipe(
	v.object({
		id: v.string(),
		data: v.optional(v.record(v.string(), v.unknown())),
		components: v.array(AuthDanceIdentityComponent),
	}),
	v.title("Identity"),
	v.description("An identity object that contains an id and associated data."),
);
