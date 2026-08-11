/**
 * @module
 *
 * The inbox slideout: every message a channel took, newest first.
 *
 * The channels of this demo never leave the browser. Instead of handing a message to a mail server or a gateway they
 * keep it, which is the only reason a one-time code the library sends is readable at all. The panel is that pile, and
 * the one control it offers carries a code back into the form so the owner never has to retype it.
 *
 * Nothing here ever leaves the machine, which is what makes the whole demo safe to hand around.
 */

import { InboxIcon } from "lucide-react";

import { focusPromptField } from "@/components/auth/prompt-fields.tsx";
import { Badge } from "@/components/ui/badge.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty.tsx";
import { Item, ItemContent, ItemDescription, ItemFooter, ItemGroup, ItemHeader } from "@/components/ui/item.tsx";
import { ScrollArea } from "@/components/ui/scroll-area.tsx";
import { useDance, useDanceActions } from "@/lib/dance/index.ts";
import { clock } from "@/lib/format.ts";

/** What the inbox asks of whoever hosts it. */
export interface InboxPanelProps {
	/** Called once a code has left the inbox for the form, so the host can close the slideout on the way out. */
	onUsed: () => void;
}

/**
 * The body of the inbox slideout.
 *
 * It owns no state. `messages` is the only thing it reads and `useCode` the only thing it calls, and neither of them
 * touches the flow in progress beyond filling one field.
 */
export function InboxPanel({ onUsed }: InboxPanelProps) {
	const { messages } = useDance();
	// `useCode` is not a react hook despite the name, so it travels under one that will not upset the linter.
	const { useCode: fillCode } = useDanceActions();

	if (messages.length === 0) {
		return (
			<div className="flex min-h-0 flex-1 items-center px-6 pb-6">
				<Empty className="border">
					<EmptyHeader>
						<EmptyMedia variant="icon">
							<InboxIcon />
						</EmptyMedia>
						<EmptyTitle>Nothing yet</EmptyTitle>
						<EmptyDescription>
							A channel here keeps its messages instead of delivering them, so a one-time code the library sends lands in this list.
						</EmptyDescription>
					</EmptyHeader>
				</Empty>
			</div>
		);
	}

	return (
		<ScrollArea className="min-h-0 flex-1">
			<ItemGroup className="gap-2 px-6 pb-6">
				{messages.map((message) => {
					// Only the otp component files a bare code under `text/x-code`, so every other message shows its subject instead.
					const code = message.code;
					return (
						<Item key={message.id} variant="outline" size="sm">
							<ItemHeader className="text-xs text-muted-foreground">
								<span className="flex min-w-0 items-center gap-2">
									<Badge variant="outline">{message.channel}</Badge>
									<span className="truncate">{message.recipient}</span>
								</span>
								<span className="shrink-0 tabular-nums">{clock(message.at)}</span>
							</ItemHeader>
							{code
								? (
									<ItemFooter>
										<code className="font-mono text-2xl tracking-widest">{code}</code>
										<Button
											variant="secondary"
											size="xs"
											onClick={() => {
												const filled = fillCode(code);
												if (filled) {
													focusPromptField(filled);
												}
												onUsed();
											}}
										>
											Use this code
										</Button>
									</ItemFooter>
								)
								: (
									<ItemContent>
										<ItemDescription>{message.subject}</ItemDescription>
									</ItemContent>
								)}
						</Item>
					);
				})}
			</ItemGroup>
		</ScrollArea>
	);
}
