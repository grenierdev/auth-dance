import { createFileRoute } from "@tanstack/react-router";
import { LogInIcon, NotebookPenIcon, RefreshCwIcon, ShieldOffIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldLabel } from "@/components/ui/field";
import { decodeJwt } from "@/lib/auth";
import { oauth2Form, useDemoInfo } from "@/lib/demo";
import { type NotesTokens, readNotesTokens, startAuthorization, writeNotesTokens } from "@/lib/notes";

export const Route = createFileRoute("/playground/")({ component: Playground });

/** Dance Notes: a third-party app that signs in with the authorization code grant and PKCE. */
function Playground() {
	const info = useDemoInfo();
	const [tokens, setTokens] = useState<NotesTokens>();
	const [askAccount, setAskAccount] = useState(true);
	const [probe, setProbe] = useState<{ status: number; body: unknown }>();

	useEffect(() => setTokens(readNotesTokens()), []);

	function keep(next: NotesTokens | undefined) {
		writeNotesTokens(next);
		setTokens(next);
		setProbe(undefined);
	}

	async function refresh() {
		const { status, body } = await oauth2Form("/oauth2/token", {
			grant_type: "refresh_token",
			refresh_token: tokens!.refresh_token!,
			client_id: info!.clients.notes,
		});
		if (status === 200) {
			keep(body);
			toast.success("New tokens from /oauth2/token");
		} else {
			toast.error(`${body.error}: ${body.error_description ?? ""}`);
		}
	}

	async function revoke() {
		await oauth2Form("/oauth2/revoke", { token: tokens!.refresh_token ?? tokens!.access_token, client_id: info!.clients.notes });
		keep(undefined);
		toast.success("The grant is revoked");
	}

	// An access token that holds `account` works on the routes of the core, like the token of a dance.
	async function listComponents() {
		const response = await fetch("/auth/list-components", {
			method: "POST",
			headers: { authorization: `Bearer ${tokens!.access_token}`, "content-type": "application/json" },
		});
		setProbe({ status: response.status, body: await response.json().catch(() => null) });
	}

	const claims = tokens ? decodeJwt(tokens.access_token) : undefined;

	return (
		<main className="mx-auto flex max-w-3xl flex-col gap-6 px-4 py-10">
			<div className="flex items-center gap-3">
				<div className="flex size-10 items-center justify-center rounded-lg bg-amber-100 text-amber-900">
					<NotebookPenIcon className="size-5" />
				</div>
				<div>
					<h1 className="text-2xl font-bold tracking-tight">Dance Notes</h1>
					<p className="text-sm text-muted-foreground">A pretend third-party app. It knows Auth Dance only through OAuth 2.0.</p>
				</div>
			</div>

			{!tokens ? (
				<Card>
					<CardHeader>
						<CardTitle>Sign in to Dance Notes</CardTitle>
						<CardDescription>
							The app sends you to <code>/oauth2/authorize</code> with a PKCE challenge. Auth Dance shows its login page, then its consent
							screen, and sends you back with a code the app exchanges at <code>/oauth2/token</code>.
						</CardDescription>
					</CardHeader>
					<CardContent>
						<Field orientation="horizontal">
							<Checkbox id="ask-account" checked={askAccount} onCheckedChange={(checked) => setAskAccount(checked === true)} />
							<FieldLabel htmlFor="ask-account">
								Also ask for <code>account</code>, the scope that manages the account
							</FieldLabel>
						</Field>
					</CardContent>
					<CardFooter>
						<Button disabled={!info} onClick={() => startAuthorization(info!.clients.notes, askAccount ? "profile account" : "profile")}>
							<LogInIcon /> Sign in with Auth Dance
						</Button>
					</CardFooter>
				</Card>
			) : (
				<Card>
					<CardHeader>
						<CardTitle>Hello {String(claims?.email ?? claims?.sub)}</CardTitle>
						<CardDescription>
							Dance Notes holds a token for <code>{String(claims?.client_id)}</code> with the scopes{" "}
							{tokens.scope.split(" ").map((scope) => (
								<Badge key={scope} variant="secondary" className="mr-1">
									{scope}
								</Badge>
							))}
						</CardDescription>
					</CardHeader>
					<CardContent className="flex flex-col gap-4">
						<pre className="overflow-x-auto rounded-lg bg-muted p-3 text-xs">{JSON.stringify(claims, null, 2)}</pre>
						{probe && (
							<div>
								<div className="mb-1 text-sm font-medium">POST /auth/list-components → {probe.status}</div>
								<pre className="max-h-64 overflow-auto rounded-lg bg-muted p-3 text-xs">{JSON.stringify(probe.body, null, 2)}</pre>
							</div>
						)}
					</CardContent>
					<CardFooter className="flex flex-wrap gap-2">
						<Button variant="outline" onClick={refresh} disabled={!tokens.refresh_token}>
							<RefreshCwIcon /> Refresh
						</Button>
						<Button variant="outline" onClick={listComponents}>
							Call the account API
						</Button>
						<Button variant="outline" onClick={revoke}>
							<ShieldOffIcon /> Revoke
						</Button>
						<Button variant="ghost" onClick={() => keep(undefined)}>
							Forget the tokens
						</Button>
					</CardFooter>
				</Card>
			)}
		</main>
	);
}
