import { CopyIcon, InboxIcon, Trash2Icon, XIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

interface Mail {
	id: string;
	at: string;
	to: string;
	subject: string;
	code?: string;
	text?: string;
}

/**
 * Toasts a new mail, and puts its code in the clipboard. Firefox and Safari refuse a write that no click started, and
 * Chrome refuses one from a page without focus: the toast then offers the copy as a button.
 */
async function announce(mail: Mail) {
	const title = `New mail to ${mail.to}`;
	const code = mail.code;
	if (!code) {
		toast(title, { description: mail.subject });
		return;
	}
	const copied = await navigator.clipboard.writeText(code).then(
		() => true,
		() => false,
	);
	toast(title, {
		description: copied ? (
			<>
				Code {code} <small>(copied)</small>
			</>
		) : (
			`Code ${code}`
		),
		action: copied ? undefined : { label: "Copy", onClick: () => navigator.clipboard.writeText(code) },
	});
}

/**
 * The inbox of the in-memory mail channel. The server sends nothing for real: every one-time code lands here, so the
 * demo runs without a mail server.
 */
export function Mailbox() {
	const [open, setOpen] = useState(false);
	const [messages, setMessages] = useState<Mail[]>([]);
	const [unread, setUnread] = useState(0);
	const seen = useRef<string | undefined>(undefined);

	useEffect(() => {
		let active = true;
		async function poll() {
			const response = await fetch("/api/mailbox").catch(() => undefined);
			const body = (await response?.json().catch(() => undefined)) as { messages: Mail[] } | undefined;
			if (!active || !body) {
				return;
			}
			setMessages(body.messages);
			const latest = body.messages[0];
			if (latest && latest.id !== seen.current) {
				if (seen.current !== undefined) {
					setUnread((count) => count + 1);
					announce(latest);
				}
				seen.current = latest.id;
			}
			if (seen.current === undefined) {
				seen.current = "";
			}
		}
		poll();
		const timer = setInterval(poll, 1500);
		return () => {
			active = false;
			clearInterval(timer);
		};
	}, []);

	if (!open) {
		return (
			<Button
				className="fixed right-4 bottom-4 z-50 shadow-lg"
				onClick={() => {
					setOpen(true);
					setUnread(0);
				}}
			>
				<InboxIcon /> Demo inbox
				{unread > 0 && <Badge variant="secondary">{unread}</Badge>}
			</Button>
		);
	}

	return (
		<Card className="fixed right-4 bottom-4 z-50 flex max-h-[70vh] w-[min(24rem,calc(100vw-2rem))] flex-col shadow-xl">
			<CardHeader>
				<CardTitle className="flex items-center gap-2">
					<InboxIcon className="size-4" /> Demo inbox
				</CardTitle>
				<CardDescription>Every mail the email channel sends lands here.</CardDescription>
				<CardAction className="flex gap-1">
					<Button
						size="icon-sm"
						variant="ghost"
						aria-label="Empty the inbox"
						onClick={async () => {
							await fetch("/api/mailbox", { method: "DELETE" });
							setMessages([]);
						}}
					>
						<Trash2Icon />
					</Button>
					<Button size="icon-sm" variant="ghost" aria-label="Close the inbox" onClick={() => setOpen(false)}>
						<XIcon />
					</Button>
				</CardAction>
			</CardHeader>
			<CardContent className="flex flex-col gap-3 overflow-y-auto">
				{messages.length === 0 && <p className="text-sm text-muted-foreground">Nothing yet. Sign up with an address to get a code.</p>}
				{messages.map((message) => (
					<div key={message.id} className="rounded-lg border p-3 text-sm">
						<div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
							<span className="truncate">To {message.to}</span>
							<span>{new Date(message.at).toLocaleTimeString()}</span>
						</div>
						<div className="mt-1 font-medium">{message.subject}</div>
						{message.code ? (
							<div className="mt-2 flex items-center justify-between">
								<code className="font-mono text-2xl tracking-[0.3em]">{message.code}</code>
								<Button
									size="sm"
									variant="outline"
									onClick={() => {
										navigator.clipboard.writeText(message.code!);
										toast.success("Code copied");
									}}
								>
									<CopyIcon /> Copy
								</Button>
							</div>
						) : (
							<p className="mt-1 text-muted-foreground">{message.text}</p>
						)}
					</div>
				))}
			</CardContent>
		</Card>
	);
}
