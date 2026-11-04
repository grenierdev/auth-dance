import { ArrowRightIcon } from "lucide-react";
import { Fragment } from "react";

export type PathState = "idle" | "ghost" | "performing" | "done";

export function Path({
	steps,
	labels,
	state,
	beatStep,
	outcome,
	trace,
	onTrace,
	fresh,
}: {
	steps: string[];
	labels?: Record<string, string>;
	state: PathState;
	beatStep: number;
	/** Shown after the last step once the path completes: what the dance hands back. */
	outcome?: string;
	/** A step name the visitor points at; every chip of that name lights. */
	trace?: string;
	onTrace?: (name: string | undefined) => void;
	/** A step the visitor just added: it is laid on the floor with a short entrance. */
	fresh?: string;
}) {
	const landed = outcome !== undefined && (state === "done" || (state === "performing" && beatStep >= steps.length));
	return (
		<span className={`flex flex-wrap items-center gap-y-2 transition-opacity duration-300 ${state === "ghost" ? "opacity-35" : "opacity-100"}`}>
			{steps.map((s, si) => {
				const isActive = state === "performing" && si === beatStep;
				const isDone = state === "done" || (state === "performing" && si < beatStep);
				const traced = trace === s;
				const tone = isActive
					? "border-accent bg-accent text-accent-fg"
					: traced
						? "border-accent bg-accent-wash text-fg"
						: isDone
							? "border-line-strong bg-surface-2 text-fg"
							: state === "idle"
								? "border-line text-muted"
								: "border-dashed border-line-strong text-faint";
				return (
					<Fragment key={s}>
						{si > 0 && (
							<span
								aria-hidden="true"
								className={`h-px w-3 transition-colors duration-300 sm:w-4 ${isActive ? "bg-accent" : isDone ? "bg-muted" : "bg-line-strong"}`}
							/>
						)}
						<span
							onMouseEnter={onTrace ? () => onTrace(s) : undefined}
							onMouseLeave={onTrace ? () => onTrace(undefined) : undefined}
							className={`rounded-[5px] border px-2 py-1 font-mono text-xs leading-none transition-[background-color,color,border-color,transform] duration-300 ease-(--ease-out-expo) ${tone} ${isActive ? "-translate-y-0.5" : ""} ${onTrace ? "cursor-default" : ""}`}
						>
							{labels?.[s] ?? s}
						</span>
					</Fragment>
				);
			})}
			{outcome !== undefined && (
				<span
					aria-hidden={!landed}
					className={`ml-2 inline-flex items-center gap-1.5 font-mono text-xs text-accent-text transition-[opacity,transform] duration-500 ease-(--ease-out-expo) ${landed ? "translate-x-0 opacity-100" : "-translate-x-1 opacity-0"}`}
				>
					<ArrowRightIcon aria-hidden="true" className="size-3" strokeWidth={1.75} />
					{outcome}
				</span>
			)}
		</span>
	);
}

