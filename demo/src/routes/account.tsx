import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import type { AuthDanceFlow, AuthDanceIdentityComponentPublic, AuthDanceResponseSessions } from "auth-dance/client";
import { useAuthDanceClient, useAuthDanceTokens } from "auth-dance/react";
import { FingerprintIcon, KeyRoundIcon, LogOutIcon, MailIcon, RefreshCwIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react";
import { type ReactNode, useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { DanceForm } from "@/components/dance-form";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { bearer, decodeJwt, describeError, emailOf } from "@/lib/auth";
import { api } from "@/lib/demo";

export const Route = createFileRoute("/account")({ component: Account });

/** One running management flow, in the dialog. */
interface RunningFlow {
	flow: AuthDanceFlow;
	name?: string;
	title: string;
	description?: string;
}

/** The steps of the choreography, as this page lists them. */
const METHODS: { name: string; label: string; icon: ReactNode; detail: string; rotate: boolean }[] = [
	{
		name: "email",
		label: "Email address",
		icon: <MailIcon />,
		detail: "Names the account. Brings the email channel and the code.",
		rotate: true,
	},
	{ name: "password", label: "Password", icon: <KeyRoundIcon />, detail: "The second step of the email branch.", rotate: true },
	{
		name: "otp",
		label: "One-time code",
		icon: <ShieldCheckIcon />,
		detail: "Mailed to the email channel. Linked to the address.",
		rotate: false,
	},
	{ name: "passkey", label: "Passkey", icon: <FingerprintIcon />, detail: "The other branch: a complete way in on its own.", rotate: true },
];

interface Grant {
	id: string;
	client_id: string;
	scopes: string[];
	expireAt: string;
	client?: { client_name?: string; client_uri?: string };
}

function Account() {
	const client = useAuthDanceClient();
	const tokens = useAuthDanceTokens();
	const navigate = useNavigate();
	const [restored, setRestored] = useState(false);
	const [components, setComponents] = useState<AuthDanceIdentityComponentPublic[]>();
	const [sessions, setSessions] = useState<AuthDanceResponseSessions>();
	const [grants, setGrants] = useState<Grant[]>();
	const [running, setRunning] = useState<RunningFlow>();
	const [failure, setFailure] = useState<unknown>();

	useEffect(() => {
		client.restore().then(() => setRestored(true));
	}, [client]);

	const signedIn = tokens !== undefined;

	const reload = useCallback(async () => {
		setFailure(undefined);
		try {
			const [listed, open, connected] = await Promise.all([
				client.listComponents(),
				client.listSessions(),
				api<Grant[] | { grants: Grant[] }>("/oauth2/grants", { token: await bearer() }),
			]);
			setComponents(listed);
			setSessions(open);
			setGrants(Array.isArray(connected) ? connected : connected.grants);
		} catch (error) {
			setFailure(error);
		}
	}, [client]);

	useEffect(() => {
		if (restored && !signedIn) {
			navigate({ to: "/login", search: { redirect: "/account" } });
		} else if (restored && signedIn) {
			reload();
		}
	}, [restored, signedIn, navigate, reload]);

	if (!tokens) {
		return null;
	}

	const claims = decodeJwt(tokens.tokens.access_token);
	const enrolled = (name: string) => components?.find((c) => c.kind !== "channel" && c.component === name);
	const emailChannel = components?.find((c) => c.kind === "channel" && c.component === "email");

	return (
		<main className="mx-auto flex max-w-5xl flex-col gap-6 px-4 py-10">
			<div className="flex flex-wrap items-end justify-between gap-4">
				<div>
					<h1 className="text-2xl font-bold tracking-tight">Account</h1>
					<p className="text-sm text-muted-foreground">
						{emailOf(tokens.tokens.access_token) ?? "No address on this account"} · <code className="text-xs">{tokens.identity.id}</code>
					</p>
				</div>
				<div className="flex gap-2">
					<Button variant="outline" onClick={reload}>
						<RefreshCwIcon /> Reload
					</Button>
					<Button
						variant="outline"
						onClick={async () => {
							await client.signOut();
							await navigate({ to: "/login" });
						}}
					>
						<LogOutIcon /> Sign out
					</Button>
				</div>
			</div>

			{failure !== undefined && (
				<Alert variant="destructive">
					<AlertTitle>{describeError(failure)}</AlertTitle>
				</Alert>
			)}

			<Card>
				<CardHeader>
					<CardTitle>Sign-in methods</CardTitle>
					<CardDescription>
						The components of the choreography. Every management flow needs a sign-in less than ten minutes old, and a removal that leaves
						no complete path is refused.
					</CardDescription>
				</CardHeader>
				<CardContent>
					<Table>
						<TableBody>
							{METHODS.map((method) => {
								const record = enrolled(method.name);
								return (
									<TableRow key={method.name}>
										<TableCell className="w-8 [&_svg]:size-4">{method.icon}</TableCell>
										<TableCell>
											<div className="font-medium">{method.label}</div>
											<div className="text-xs whitespace-normal text-muted-foreground">
												{record?.kind === "identification" && method.name === "email" ? record.identification : method.detail}
											</div>
										</TableCell>
										<TableCell>
											{components === undefined ? null : record ? (
												<Badge variant={record.confirmed ? "default" : "outline"}>{record.confirmed ? "Enrolled" : "Unconfirmed"}</Badge>
											) : (
												<Badge variant="outline">Not set up</Badge>
											)}
										</TableCell>
										<TableCell className="text-right">
											<div className="flex justify-end gap-1.5">
												{record ? (
													<>
														{method.rotate && (
															<Button
																size="sm"
																variant="outline"
																onClick={() =>
																	setRunning({ flow: "rotate", name: method.name, title: `Change your ${method.label.toLowerCase()}` })
																}
															>
																Change
															</Button>
														)}
														<Button
															size="sm"
															variant="ghost"
															onClick={() =>
																setRunning({ flow: "unenroll", name: method.name, title: `Remove your ${method.label.toLowerCase()}` })
															}
														>
															Remove
														</Button>
													</>
												) : (
													<Button
														size="sm"
														onClick={() =>
															setRunning({ flow: "enroll", name: method.name, title: `Add your ${method.label.toLowerCase()}` })
														}
													>
														Set up
													</Button>
												)}
											</div>
										</TableCell>
									</TableRow>
								);
							})}
						</TableBody>
					</Table>
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle>Channels</CardTitle>
					<CardDescription>
						Where the codes go. The email address brings its channel with it; an account without one subscribes it here, and the code proves
						the address.
					</CardDescription>
				</CardHeader>
				<CardContent className="flex items-center justify-between gap-4">
					<div className="flex items-center gap-2">
						<MailIcon className="size-4" />
						<span className="font-medium">email</span>
						{emailChannel ? <Badge>Subscribed</Badge> : <Badge variant="outline">Not subscribed</Badge>}
						{emailChannel?.linkedTo && <span className="text-xs text-muted-foreground">linked to {emailChannel.linkedTo.join(", ")}</span>}
					</div>
					{emailChannel ? (
						<Button
							size="sm"
							variant="ghost"
							onClick={() => setRunning({ flow: "unsubscribe", name: "email", title: "Unsubscribe the email channel" })}
						>
							Unsubscribe
						</Button>
					) : (
						<Button size="sm" onClick={() => setRunning({ flow: "subscribe", name: "email", title: "Subscribe an email channel" })}>
							Subscribe
						</Button>
					)}
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle>Sessions</CardTitle>
					<CardDescription>Every session open on this account, from the dance. The grants of connected apps stand apart.</CardDescription>
					<CardAction>
						<Button
							size="sm"
							variant="outline"
							onClick={async () => {
								await client.signOut({ others: true });
								toast.success("Every session is closed");
								await navigate({ to: "/login" });
							}}
						>
							Sign out everywhere
						</Button>
					</CardAction>
				</CardHeader>
				<CardContent>
					<Table>
						<TableHeader>
							<TableRow>
								<TableHead>Session</TableHead>
								<TableHead>Address</TableHead>
								<TableHead>Browser</TableHead>
								<TableHead>Ends</TableHead>
							</TableRow>
						</TableHeader>
						<TableBody>
							{sessions?.sessions.map((session) => (
								<TableRow key={session.id}>
									<TableCell className="font-mono text-xs">
										{session.id.slice(0, 16)}… {session.id === sessions.current && <Badge className="ml-1">This one</Badge>}
									</TableCell>
									<TableCell>{session.address ?? "?"}</TableCell>
									<TableCell className="max-w-56 truncate text-xs text-muted-foreground" title={session.userAgent}>
										{session.userAgent ?? "?"}
									</TableCell>
									<TableCell className="text-xs">{new Date(session.expireAt).toLocaleString()}</TableCell>
								</TableRow>
							))}
						</TableBody>
					</Table>
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle>Connected apps</CardTitle>
					<CardDescription>
						The OAuth 2.0 grants you consented to. Revoking one ends its session and forgets the consent you asked to remember.
					</CardDescription>
				</CardHeader>
				<CardContent>
					{grants?.length === 0 && (
						<p className="text-sm text-muted-foreground">
							No app has access. Try <Link to="/playground">Dance Notes</Link> or <Link to="/tv">Dance TV</Link>.
						</p>
					)}
					<div className="flex flex-col gap-2">
						{grants?.map((grant) => (
							<div key={grant.id} className="flex items-center justify-between gap-4 rounded-lg border p-3">
								<div>
									<div className="font-medium">{grant.client?.client_name ?? grant.client_id}</div>
									<div className="flex flex-wrap gap-1 pt-1">
										{grant.scopes.map((scope) => (
											<Badge key={scope} variant="secondary">
												{scope}
											</Badge>
										))}
									</div>
								</div>
								<Button
									size="sm"
									variant="outline"
									onClick={async () => {
										try {
											await api(`/oauth2/grants/${encodeURIComponent(grant.id)}`, { method: "DELETE", token: await bearer() });
											toast.success(`${grant.client?.client_name ?? "The app"} lost its access`);
										} catch (error) {
											toast.error(describeError(error));
										}
										await reload();
									}}
								>
									Revoke
								</Button>
							</div>
						))}
					</div>
				</CardContent>
			</Card>

			<Card>
				<CardHeader>
					<CardTitle>Tokens</CardTitle>
					<CardDescription>
						The access token is a JWT (RFC 9068) the server signs with an asymmetric key. A refresh mints a new pair on the same session,
						and keeps <code>auth_time</code>.
					</CardDescription>
					<CardAction>
						<Button
							size="sm"
							variant="outline"
							onClick={async () => {
								try {
									await client.refreshTokens();
									toast.success("New tokens");
								} catch (error) {
									toast.error(describeError(error));
								}
							}}
						>
							<RefreshCwIcon /> Refresh
						</Button>
					</CardAction>
				</CardHeader>
				<CardContent>
					<pre className="overflow-x-auto rounded-lg bg-muted p-3 text-xs">{JSON.stringify(claims, null, 2)}</pre>
				</CardContent>
			</Card>

			<Card className="border-destructive/40">
				<CardHeader>
					<CardTitle>Delete the account</CardTitle>
					<CardDescription>Removes the identity, every session and every grant.</CardDescription>
					<CardAction>
						<Button variant="destructive" size="sm" onClick={() => setRunning({ flow: "delete", title: "Delete your account" })}>
							<Trash2Icon /> Delete
						</Button>
					</CardAction>
				</CardHeader>
			</Card>

			<Dialog open={running !== undefined} onOpenChange={(open) => !open && setRunning(undefined)}>
				<DialogContent className="sm:max-w-sm">
					<DialogTitle className="sr-only">{running?.title}</DialogTitle>
					{running && (
						<DanceForm
							key={`${running.flow}-${running.name}`}
							compact
							flow={running.flow}
							name={running.name}
							title={running.title}
							description={running.description}
							onDone={async () => {
								toast.success(`${running.title}: done`);
								setRunning(undefined);
								if (running.flow === "delete") {
									await navigate({ to: "/" });
									return;
								}
								// The claims of a token come from the identity when it is minted: a new address shows after a refresh.
								await client.refreshTokens().catch(() => undefined);
								await reload();
							}}
						/>
					)}
				</DialogContent>
			</Dialog>
		</main>
	);
}
