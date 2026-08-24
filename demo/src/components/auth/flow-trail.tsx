/**
 * @module
 *
 * The progress trail of a running flow. A choreography is a tree, so the count of steps is not known at the start. The
 * trail shows every name the store collected, plus the one on screen.
 */

import type { Step } from "@/lib/dance/index.ts";
import { cn } from "@/lib/utils.ts";

/** One row of small pills. The answered names are muted and the pending one is accented. */
export function FlowTrail({ step }: { step: Step }) {
	// A choice has no name of its own until a branch is answered.
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
