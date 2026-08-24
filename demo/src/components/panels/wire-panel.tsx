/**
 * @module
 *
 * The wire slideout: every call into the library, and everything its hooks report, newest first.
 */

import type { ComponentProps } from "react";
import { ChevronRightIcon, EraserIcon, RadioTowerIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible.tsx";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty.tsx";
import { ScrollArea } from "@/components/ui/scroll-area.tsx";
import { type LogEntry, useDance, useDanceActions } from "@/lib/dance/index.ts";
import { clock } from "@/lib/format.ts";

/** How many lines the panel renders. The log itself is unbounded. */
const SHOWN = 40;

/** The body of the wire sheet. It fills the height of the sheet and scrolls on the inside. */
export function WirePanel() {
	const { log } = useDance();
	const { clearLog } = useDanceActions();
	const lines = log.slice(0, SHOWN);

	return (
		<div className="flex h-full min-h-0 min-w-0 flex-col gap-3">
			<div className="flex items-center justify-between gap-2">
				<p className="text-xs text-muted-foreground">{summarise(log.length, lines.length)}</p>
				<Button variant="outline" size="xs" disabled={log.length === 0} onClick={() => void clearLog()}>
					<EraserIcon />
					Clear
				</Button>
			</div>

			{lines.length === 0
				? (
					<Empty className="min-h-0 flex-1 border p-8">
						<EmptyHeader>
							<EmptyMedia variant="icon">
								<RadioTowerIcon />
							</EmptyMedia>
							<EmptyTitle>Nothing on the wire</EmptyTitle>
							<EmptyDescription>Every call into the library, and everything its hooks report, shows up here.</EmptyDescription>
						</EmptyHeader>
					</Empty>
				)
				: (
					<ScrollArea className="min-h-0 flex-1">
						<div className="flex w-full min-w-0 flex-col gap-2 pr-3">
							{lines.map((entry) => <WireLine key={entry.id} entry={entry} />)}
						</div>
					</ScrollArea>
				)}
		</div>
	);
}

/** One line of the log, closed until the owner asks for the bodies. */
function WireLine({ entry }: { entry: LogEntry }) {
	return (
		<Collapsible className="min-w-0 rounded-xl border bg-card">
			<CollapsibleTrigger className="group/line flex w-full min-w-0 items-center gap-2 rounded-xl px-3 py-2 text-left outline-none transition-colors hover:bg-muted/50 focus-visible:ring-3 focus-visible:ring-ring/30">
				<ChevronRightIcon className="size-3.5 shrink-0 text-muted-foreground transition-transform group-data-[panel-open]/line:rotate-90" />
				<Badge variant={tone(entry)} className="shrink-0 font-mono">{status(entry)}</Badge>
				<span className="min-w-0 flex-1 truncate font-mono text-xs">{entry.label}</span>
				{entry.ms !== undefined && <span className="shrink-0 font-mono text-xs tabular-nums text-muted-foreground">{entry.ms} ms</span>}
				<span className="shrink-0 font-mono text-xs tabular-nums text-muted-foreground">{clock(entry.at)}</span>
			</CollapsibleTrigger>
			<CollapsibleContent className="h-[var(--collapsible-panel-height)] overflow-hidden transition-[height] duration-200 data-ending-style:h-0 data-starting-style:h-0">
				<div className="flex min-w-0 flex-col gap-2 border-t px-3 py-2">
					{entry.request !== undefined && <WireBody label="request" body={entry.request} />}
					{entry.response !== undefined && <WireBody label="response" body={entry.response} />}
					{entry.request === undefined && entry.response === undefined && (
						<p className="text-xs text-muted-foreground">The line carried no body.</p>
					)}
				</div>
			</CollapsibleContent>
		</Collapsible>
	);
}

/** One body, pretty-printed. It scrolls on its own axis. */
function WireBody({ label, body }: { label: string; body: unknown }) {
	return (
		<div className="flex min-w-0 flex-col gap-1">
			<span className="font-mono text-xs text-muted-foreground">{label}</span>
			<pre className="w-full max-w-full min-w-0 overflow-x-auto rounded-lg bg-muted p-2 font-mono text-xs leading-relaxed">{print(body)}</pre>
		</div>
	);
}

/** The tone of the badge. A hook stays quiet, an answered call is affirmative, everything else is a refusal. */
function tone(entry: LogEntry): ComponentProps<typeof Badge>["variant"] {
	if (entry.kind === "hook") {
		return "secondary";
	}
	return entry.status === 200 ? "default" : "destructive";
}

function status(entry: LogEntry): string {
	if (entry.kind === "hook") {
		return "hook";
	}
	return entry.status === undefined ? "—" : String(entry.status);
}

function print(body: unknown): string {
	return JSON.stringify(body, undefined, 2) ?? String(body);
}

/** The line above the list: how much of the log is on screen. */
function summarise(total: number, shown: number): string {
	if (total === 0) {
		return "Nothing yet";
	}
	if (total > shown) {
		return `Newest ${shown} of ${total} lines`;
	}
	return total === 1 ? "1 line" : `${total} lines, newest first`;
}
