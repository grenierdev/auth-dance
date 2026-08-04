/**
 * @module
 *
 * The progress trail of a running flow.
 *
 * A choreography is a tree, so the number of steps is not known when the flow starts. The trail is therefore a record of
 * what has been answered rather than a plan: every name the store collected, plus the one on screen. A name that had to
 * prove control of itself already carries its check mark, so this only lays them out.
 */

import type { Step } from "@/lib/dance";
import { cn } from "@/lib/utils";

/** One row of small pills, the answered names muted and the pending one accented. Scrolls sideways when the flow is long. */
export function FlowTrail({ step }: { step: Step }) {
	// A choice has no name of its own until a branch is answered, so the pending pill says what it is instead.
	const pending = step.prompt.kind === "input" ? step.prompt.name : "choice";

	return (
		<ol aria-label="Steps answered so far" className="flex w-full items-center gap-1.5 overflow-x-auto pb-0.5 text-xs">
			{[...step.trail, pending].map((name, index) => {
				const answered = index < step.trail.length;
				return (
					<li key={`${name}-${index}`} className="flex shrink-0 items-center gap-1.5">
						{index > 0 && <span aria-hidden="true" className="h-px w-3 shrink-0 bg-border" />}
						<span
							aria-current={answered ? undefined : "step"}
							className={cn(
								"rounded-full px-2 py-0.5 font-mono whitespace-nowrap",
								answered ? "bg-muted text-muted-foreground" : "bg-primary/10 text-primary ring-1 ring-primary/20",
							)}
						>
							{name}
						</span>
					</li>
				);
			})}
		</ol>
	);
}
