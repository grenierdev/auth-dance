import * as v from "valibot";

// Every component splits in two: what the identity holds, and what a client may be told about it. The
// difference is `data`, the component's own private store — PasswordAuthDanceComponent keeps the hash there,
// OtpAuthDanceComponent its pending code — so the `…Public` half of each pair is the stored shape minus that
// one field, and the stored shape is declared by extending it. Sharing the field list this way is what
// keeps the two from drifting apart.
const IdentityDataField = { data: v.optional(v.record(v.string(), v.unknown())) };

export interface IdentityIdentificationPublic {
	kind: "identification";
	component: string;
	identification: string;
	confirmed: boolean;
}

export interface IdentityIdentification extends IdentityIdentificationPublic {
	data?: Record<string, unknown>;
}

const IdentityIdentificationFields = {
	kind: v.literal("identification"),
	component: v.string(),
	identification: v.string(),
	confirmed: v.boolean(),
} as const;

export const IdentityIdentification: v.GenericSchema<IdentityIdentification> = v.pipe(
	v.object({ ...IdentityIdentificationFields, ...IdentityDataField }),
	v.title("IdentityIdentification"),
	v.description(
		"An identity identification object that contains an identity id, component, identification, confirmation status, and associated data.",
	),
);

export const IdentityIdentificationPublic: v.GenericSchema<IdentityIdentificationPublic> = v.pipe(
	v.object(IdentityIdentificationFields),
	v.title("IdentityIdentificationPublic"),
	v.description("An identity identification as disclosed to a client: its component, identification and confirmation status."),
);

export interface IdentityChallengePublic {
	kind: "challenge";
	component: string;
	confirmed: boolean;
}

export interface IdentityChallenge extends IdentityChallengePublic {
	data?: Record<string, unknown>;
}

const IdentityChallengeFields = {
	kind: v.literal("challenge"),
	component: v.string(),
	confirmed: v.boolean(),
} as const;

export const IdentityChallenge: v.GenericSchema<IdentityChallenge> = v.pipe(
	v.object({ ...IdentityChallengeFields, ...IdentityDataField }),
	v.title("IdentityChallenge"),
	v.description(
		"An identity challenge object that contains an identity id, component, confirmation status, and associated data.",
	),
);

export const IdentityChallengePublic: v.GenericSchema<IdentityChallengePublic> = v.pipe(
	v.object(IdentityChallengeFields),
	v.title("IdentityChallengePublic"),
	v.description("An identity challenge as disclosed to a client: its component and confirmation status, never the secret it verifies."),
);

export interface IdentityChannelPublic {
	kind: "channel";
	channel: string;
	confirmed: boolean;
	linkedTo?: string[];
}

export interface IdentityChannel extends IdentityChannelPublic {
	data?: Record<string, unknown>;
}

const IdentityChannelFields = {
	kind: v.literal("channel"),
	channel: v.string(),
	confirmed: v.boolean(),
	linkedTo: v.optional(v.array(v.string())),
} as const;

export const IdentityChannel: v.GenericSchema<IdentityChannel> = v.pipe(
	v.object({ ...IdentityChannelFields, ...IdentityDataField }),
	v.title("IdentityChannel"),
	v.description(
		"An identity channel object that contains an identity id, channel, confirmation status, associated data, and the names of the components that depend on it.",
	),
);

export const IdentityChannelPublic: v.GenericSchema<IdentityChannelPublic> = v.pipe(
	v.object(IdentityChannelFields),
	v.title("IdentityChannelPublic"),
	v.description(
		"An identity channel as disclosed to a client: its channel, confirmation status, and the components that depend on it — never the recipient itself.",
	),
);

export type IdentityComponent = IdentityIdentification | IdentityChallenge | IdentityChannel;

export const IdentityComponent: v.GenericSchema<IdentityComponent> = v.pipe(
	v.union([
		IdentityIdentification,
		IdentityChallenge,
		IdentityChannel,
	]),
	v.title("IdentityComponent"),
	v.description(
		"An identity component object that can be either an identity identification, an identity challenge, or an identity channel.",
	),
);

export type IdentityComponentPublic = IdentityIdentificationPublic | IdentityChallengePublic | IdentityChannelPublic;

export const IdentityComponentPublic: v.GenericSchema<IdentityComponentPublic> = v.pipe(
	v.union([
		IdentityIdentificationPublic,
		IdentityChallengePublic,
		IdentityChannelPublic,
	]),
	v.title("IdentityComponentPublic"),
	v.description(
		"An identity component as disclosed to a client — an identification, a challenge or a channel — without the component's private data.",
	),
);

export interface Identity {
	id: string;
	data?: Record<string, unknown>;
	components: IdentityComponent[];
}

export const Identity: v.GenericSchema<Identity> = v.pipe(
	v.object({
		id: v.string(),
		data: v.optional(v.record(v.string(), v.unknown())),
		components: v.array(IdentityComponent),
	}),
	v.title("Identity"),
	v.description("An identity object that contains an id and associated data."),
);
