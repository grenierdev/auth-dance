/**
 * @module
 *
 * The inbox slideout: every message a channel took, newest first. A channel of this demo keeps its messages in the
 * browser and delivers nothing, which is why a one-time code is readable here.
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
	/** Called after a code goes from the inbox to the form, so the host can close the slideout. */
	onUsed: () => void;
}

/** The body of the inbox slideout. It owns no state. */
export function InboxPanel({ onUsed }: InboxPanelProps) {
	const { messages } = useDance();
	// `useCode` is not a react hook despite the name.
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
					// Only the otp component files a bare code. Every other message shows its subject.
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
