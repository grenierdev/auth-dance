/**
 * @module
 *
 * The body of the session slideout. Signed out it says where the tokens will appear. Signed in it shows the identity,
 * the session, the three tokens, and whatever `/list-sessions` and `/list-components` last answered.
 */

import { useEffect, useState } from "react";
import { CheckIcon, CopyIcon, KeyRoundIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty.tsx";
import { Item, ItemActions, ItemContent, ItemDescription, ItemGroup, ItemTitle } from "@/components/ui/item.tsx";
import { ScrollArea } from "@/components/ui/scroll-area.tsx";
import { Separator } from "@/components/ui/separator.tsx";
import { Skeleton } from "@/components/ui/skeleton.tsx";
import { useDance, useDanceActions } from "@/lib/dance/index.ts";
import { stamp } from "@/lib/format.ts";

/** The three tokens, in the order the library mints them. */
const TOKEN_NAMES = ["access_token", "id_token", "refresh_token"] as const;

/** How long the copy button stays acknowledged, in milliseconds. */
const COPIED_MS = 1200;

/** Shortens a value. It keeps both ends and replaces the middle. */
function middle(value: string, keep = 12): string {
	return value.length <= keep * 2 + 1 ? value : `${value.slice(0, keep)}…${value.slice(-keep)}`;
}

/** The session slideout: what the running instance knows about the caller, and the two lists it can answer with. */
export function SessionPanel() {
	const { ready, tokens, session, sessions, enrolled, busy } = useDance();
	const { listSessions, listComponents } = useDanceActions();
	const [copied, setCopied] = useState<string | undefined>(undefined);

	useEffect(() => {
		if (copied === undefined) {
			return;
		}
		const timer = setTimeout(() => setCopied(undefined), COPIED_MS);
		return () => clearTimeout(timer);
	}, [copied]);

	if (!ready) {
		return (
			<div className="flex flex-col gap-3 px-6 pb-6">
				<Skeleton className="h-4 w-2/3" />
				<Skeleton className="h-4 w-1/2" />
				<Skeleton className="h-20 w-full" />
			</div>
		);
	}

	if (!tokens) {
		return (
			<div className="min-h-0 flex-1 px-6 pb-6">
				<Empty className="border">
					<EmptyHeader>
						<EmptyMedia variant="icon">
							<KeyRoundIcon />
						</EmptyMedia>
						<EmptyTitle>No session</EmptyTitle>
						<EmptyDescription>
							Sign in or sign up, and the tokens the library mints show up here.
						</EmptyDescription>
					</EmptyHeader>
				</Empty>
			</div>
		);
	}

	return (
		<ScrollArea className="min-h-0 flex-1">
			<div className="flex flex-col gap-4 px-6 pb-6">
				<dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
					<dt className="text-muted-foreground">identity</dt>
					<dd className="font-mono break-all">{session?.identity.id ?? "—"}</dd>
					<dt className="text-muted-foreground">session</dt>
					<dd className="font-mono break-all">{session?.session.id ?? "—"}</dd>
					<dt className="text-muted-foreground">address</dt>
					<dd className="font-mono break-all">{session?.session.address ?? "—"}</dd>
				</dl>

				<Separator />

				<div className="flex flex-col gap-1.5">
					{TOKEN_NAMES.map((name) => (
						<div key={name} className="flex items-center gap-2">
							<Badge variant="outline" className="font-mono">{name}</Badge>
							<code className="min-w-0 flex-1 truncate text-xs text-muted-foreground">{middle(tokens[name])}</code>
							<Button
								type="button"
								variant="ghost"
								size="icon-xs"
								aria-label={`Copy ${name}`}
								onClick={() => {
									void navigator.clipboard?.writeText(tokens[name]);
									setCopied(name);
								}}
							>
								{copied === name ? <CheckIcon /> : <CopyIcon />}
							</Button>
						</div>
					))}
				</div>

				<div className="flex flex-wrap gap-2">
					<Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => void listSessions()}>
						List sessions
					</Button>
					<Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => void listComponents()}>
						List components
					</Button>
				</div>

				{sessions && (
					<div className="flex flex-col gap-2">
						<h3 className="text-sm font-medium">Sessions</h3>
						{sessions.length === 0
							? <p className="text-xs text-muted-foreground">The identity holds no open session.</p>
							: (
								<ItemGroup className="gap-2">
									{sessions.map((entry) => (
										<Item key={entry.id} variant="muted" size="xs">
											<ItemContent>
												<ItemTitle className="w-full font-mono text-xs break-all">{entry.id}</ItemTitle>
												<ItemDescription className="text-xs">
													expires {stamp(entry.expireAt)}
													{entry.scopes.length > 0 && ` · ${entry.scopes.join(" ")}`}
												</ItemDescription>
											</ItemContent>
											{entry.id === session?.session.id && (
												<ItemActions>
													<Badge variant="secondary">this one</Badge>
												</ItemActions>
											)}
										</Item>
									))}
								</ItemGroup>
							)}
					</div>
				)}

				{enrolled && (
					<div className="flex flex-col gap-2">
						<h3 className="text-sm font-medium">Components</h3>
						{enrolled.length === 0
							? <p className="text-xs text-muted-foreground">The identity carries no component.</p>
							: (
								<ItemGroup className="gap-2">
									{enrolled.map((entry, index) => (
										<Item key={`${entry.kind}-${entry.component}-${index}`} variant="muted" size="xs">
											<Badge variant="outline">{entry.kind}</Badge>
											<ItemContent>
												<ItemTitle className="font-mono text-xs">{entry.component}</ItemTitle>
												{entry.kind === "identification" && (
													<ItemDescription className="text-xs break-all">{entry.identification}</ItemDescription>
												)}
												{entry.kind === "channel" && entry.linkedTo && entry.linkedTo.length > 0 && (
													<ItemDescription className="text-xs">carries {entry.linkedTo.join(", ")}</ItemDescription>
												)}
											</ItemContent>
											<ItemActions>
												<span className="text-xs text-muted-foreground">{entry.confirmed ? "confirmed" : "unconfirmed"}</span>
											</ItemActions>
										</Item>
									))}
								</ItemGroup>
							)}
					</div>
				)}
			</div>
		</ScrollArea>
	);
}
