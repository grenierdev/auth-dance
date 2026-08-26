/**
 * @module
 *
 * The card of a running flow.
 *
 * {@link useAuthDanceFlow} of `auth-dance/react` starts the flow when this node mounts, drives it, and renders again
 * every time the dance moves. It keeps whatever an action was refused with under `error`, so the alert of this card
 * reads a refused answer off the same object the body renders from.
 */

import { TriangleAlertIcon } from "lucide-react";
import { type AuthDanceFlow, useAuthDanceFlow } from "auth-dance/react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Skeleton } from "@/components/ui/skeleton.tsx";
import { describeFailure, FLOW_LABELS, useDanceActions } from "@/lib/dance/index.ts";

import { PromptForm } from "./prompt-form.tsx";

/** What the stage hands the card of a running flow. */
export interface FlowCardProps {
	/** The flow to start, under the name its route uses. */
	flow: AuthDanceFlow;
	/** The component or the channel the flow acts on. Seven of the nine flows name one. */
	name?: string;
	/** Called once the owner is done with the card: the flow ended, or the owner dropped it. */
	onLeave: () => void;
}

/** The card of one dance, from the call that starts the flow to the answer that ends it. */
export function FlowCard({ flow, name, onLeave }: FlowCardProps) {
	const { notify } = useDanceActions();
	const handle = useAuthDanceFlow({
		flow,
		name,
		onDone: (response) => {
			notify(
				"tokens" in response
					? `Signed in as ${response.identity.id}. The session panel holds the tokens.`
					: `${FLOW_LABELS[flow]} completed.`,
			);
			onLeave();
		},
	});

	// The start of the flow was refused, so there is no dance to drive. `restart` calls that route again.
	const stalled = handle.error !== undefined && handle.choreography === undefined;

	return (
		<Card>
			<CardHeader className="text-center">
				<CardTitle className="text-xl">{FLOW_LABELS[flow]}</CardTitle>
				<CardDescription>
					{name
						? (
							<>
								On <span className="font-mono">{name}</span>.
							</>
						)
						: null}
					One step of the choreography. Every answer earns the next prompt, or the tokens at the end.
				</CardDescription>
			</CardHeader>

			{(handle.error !== undefined || handle.expired) && (
				<div className="flex flex-col gap-2 px-(--card-spacing)">
					{handle.error !== undefined && (
						<Alert variant="destructive">
							<TriangleAlertIcon />
							<AlertTitle>The library refused</AlertTitle>
							<AlertDescription>{describeFailure(handle.error)}</AlertDescription>
						</Alert>
					)}
					{handle.expired && (
						<Alert variant="destructive">
							<TriangleAlertIcon />
							<AlertTitle>The flow expired</AlertTitle>
							<AlertDescription>
								The library refuses this state from now on. Take the flow from the top, and it hands out a fresh one.
							</AlertDescription>
						</Alert>
					)}
				</div>
			)}

			<CardContent>
				{handle.choreography === undefined
					? (
						stalled
							? <p className="text-sm text-muted-foreground">Nothing was started, so there is no prompt to answer.</p>
							: (
								<div className="flex flex-col gap-3">
									<Skeleton className="h-9 w-full rounded-3xl" />
									<Skeleton className="h-9 w-full rounded-3xl" />
								</div>
							)
					)
					: <PromptForm flow={handle} onLeave={onLeave} />}

				{(stalled || handle.expired) && (
					<div className="mt-4 flex flex-wrap justify-center gap-2">
						<Button type="button" size="sm" disabled={handle.pending} onClick={() => void handle.restart()}>
							Start over
						</Button>
						<Button type="button" size="sm" variant="ghost" onClick={onLeave}>
							Leave
						</Button>
					</div>
				)}
			</CardContent>
		</Card>
	);
}
