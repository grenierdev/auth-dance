/**
 * @module
 *
 * The few things every panel prints the same way. Each helper takes a `Date` or an ISO string.
 */

import { type Config, currentChoreography, formatChoreography } from "@/lib/dance/index.ts";

/** A moment as a bare wall clock, without a meridiem. Use it for anything the owner watches happen. */
export function clock(at: Date | string): string {
	return new Date(at).toLocaleTimeString(undefined, { hour12: false });
}

/** A moment as a date and a wall clock. Use it for anything that can outlive the sitting, such as a session. */
export function stamp(at: Date | string): string {
	return new Date(at).toLocaleString(undefined, { hour12: false });
}

/** A choreography drawn as text, or the reason it could not be. */
export interface ResolvedTree {
	/** Whether the config resolved to a tree. */
	ok: boolean;
	/** The drawn tree, or the message the parser refused with. */
	text: string;
}

/** Draws the tree a config resolves to, or the text of the refusal in its place. This function never throws. */
export function resolvedTree(config: Config): ResolvedTree {
	try {
		return { ok: true, text: formatChoreography(currentChoreography(config)) };
	} catch (cause) {
		return { ok: false, text: (cause as Error).message };
	}
}
