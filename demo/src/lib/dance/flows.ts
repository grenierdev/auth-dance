/**
 * @module
 *
 * What the page shows for each of the nine flows.
 *
 * `AuthDanceFlows` of `auth-dance/client` already holds the route of every flow, whether the start carries a bearer
 * token, and what its body names. This module adds only what the library has no opinion about: the label a button
 * shows, and whether a step is worth a send button.
 */

import { type AuthDanceFlow, AuthDanceFlows } from "auth-dance/client";
import type { AuthDanceFlowHandle } from "auth-dance/react";

/** What the button of each flow shows. Every key of `AuthDanceFlows` needs one. */
export const FLOW_LABELS: Record<AuthDanceFlow, string> = {
	"sign-in": "Sign in",
	"sign-up": "Sign up",
	"recover": "Recover",
	"enroll": "Enroll",
	"unenroll": "Unenroll",
	"rotate": "Rotate",
	"subscribe": "Subscribe",
	"unsubscribe": "Unsubscribe",
	"delete": "Delete identity",
};

/** The flow names, in the order the start card lists them. */
export const FLOW_NAMES: AuthDanceFlow[] = Object.keys(AuthDanceFlows) as AuthDanceFlow[];

/**
 * Whether the step on screen is worth a send button. `sendable` alone does not mean there is something to deliver, so
 * this also asks for a one-time code, which is the one type this demo can deliver.
 *
 * @param flow - The dance the card renders.
 * @returns `true` when the library holds something to deliver over a channel.
 */
export function isSendable(flow: AuthDanceFlowHandle): boolean {
	return flow.current?.sendable === true && flow.current.type === "otp";
}
