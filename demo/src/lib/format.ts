/**
 * @module
 *
 * The few things every panel prints the same way.
 *
 * Four panels each grew a clock of their own during the port, and two of them disagreed about whether it took a `Date`
 * or an ISO string. The library answers with both — a message carries a `Date` the store stamped, a session and a flow
 * carry the string the wire serialized — so the one helper takes either and the panels stop choosing.
 *
 * Nothing here reads state or renders anything. It is pure formatting, which is why it sits beside the store rather
 * than inside it.
 */

import { type Config, currentChoreography, formatChoreography } from "@/lib/dance";

/**
 * A moment as a bare wall clock, without a meridiem so the column keeps its width.
 *
 * Use it for anything the owner is watching happen: a message that just arrived, a line on the wire, a flow that
 * expires in the next few minutes.
 */
export function clock(at: Date | string): string {
	return new Date(at).toLocaleTimeString(undefined, { hour12: false });
}

/**
 * A moment as a date and a wall clock.
 *
 * A session lives as long as its refresh token, which is a day by default, so a bare clock on one reads as today and
 * means tomorrow. Anything that can outlive the sitting gets the date with it.
 */
export function stamp(at: Date | string): string {
	return new Date(at).toLocaleString(undefined, { hour12: false });
}

/** A choreography drawn as text, or the reason it could not be. */
export interface ResolvedTree {
	/** Whether the config resolved to a tree. A custom entry that is not valid JSON, or not a tree, is the only way this is false. */
	ok: boolean;
	/** The drawn tree, or the message the parser refused with, which names the path of the bad node. */
	text: string;
}

/**
 * Draws the tree a config resolves to, and turns a refusal into the text in its place.
 *
 * Both the strip under the login card and the preview in the options panel show a tree the owner may be halfway
 * through breaking, so neither can afford to throw. The failure is worth reading, so it is what gets drawn.
 */
export function resolvedTree(config: Config): ResolvedTree {
	try {
		return { ok: true, text: formatChoreography(currentChoreography(config)) };
	} catch (cause) {
		return { ok: false, text: (cause as Error).message };
	}
}
