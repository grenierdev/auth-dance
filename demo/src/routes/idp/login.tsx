import { createFileRoute } from "@tanstack/react-router";
import { useAuthDanceTokens } from "auth-dance/react";
import { Loader2Icon } from "lucide-react";
import { useEffect, useState } from "react";
import { AuthLayout } from "@/components/auth-layout";
import { ClientCard, type PublicClient } from "@/components/client-card";
import { SignInForm } from "@/components/sign-in-form";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldGroup } from "@/components/ui/field";
import { bearer, client, describeError, emailOf } from "@/lib/auth";
import { api } from "@/lib/demo";

interface LoginRequest {
	challenge: string;
	client: PublicClient;
	requested_scope: string[];
	user_code?: string;
}

export const Route = createFileRoute("/idp/login")({
	validateSearch: (search: Record<string, unknown>): { login_challenge: string } => ({
		login_challenge: typeof search.login_challenge === "string" ? search.login_challenge : "",
	}),
	component: IdpLogin,
});

/**
 * `ui.login` of the authorization server. `/oauth2/authorize` sends the browser here with a `login_challenge`. The
 * owner dances against the core, or keeps the session the page already holds, and the page hands the access token of
 * that session to the authorization server.
 */
function IdpLogin() {
	const { login_challenge } = Route.useSearch();
	const tokens = useAuthDanceTokens();
	const [request, setRequest] = useState<LoginRequest>();
	const [failure, setFailure] = useState<unknown>();
	const [anotherAccount, setAnotherAccount] = useState(false);
	const [pending, setPending] = useState(false);

	useEffect(() => {
		api<LoginRequest>(`/api/idp/login?challenge=${encodeURIComponent(login_challenge)}`).then(setRequest, setFailure);
	}, [login_challenge]);

	async function accept() {
		setPending(true);
		try {
			const { redirect_to } = await api<{ redirect_to: string }>("/api/idp/login/accept", {
				method: "POST",
				token: await bearer(),
				json: { challenge: login_challenge },
			});
			window.location.assign(redirect_to);
		} catch (error) {
			setFailure(error);
			setPending(false);
		}
	}

	async function reject() {
		const { redirect_to } = await api<{ redirect_to: string }>("/api/idp/login/reject", {
			method: "POST",
			json: { challenge: login_challenge },
		});
		window.location.assign(redirect_to);
	}

	if (failure !== undefined && !request) {
		return (
			<AuthLayout>
				<Alert variant="destructive">
					<AlertTitle>{describeError(failure)}</AlertTitle>
				</Alert>
			</AuthLayout>
		);
	}
	if (!request) {
		return (
			<AuthLayout>
				<Loader2Icon className="mx-auto size-5 animate-spin text-muted-foreground" />
			</AuthLayout>
		);
	}

	const card = <ClientCard client={request.client} scopes={request.requested_scope} userCode={request.user_code} />;
	const cancel = (
		<Button variant="ghost" size="sm" className="self-center" onClick={reject}>
			Cancel and go back
		</Button>
	);

	if (tokens && !anotherAccount) {
		return (
			<AuthLayout>
				<FieldGroup>
					<h1 className="text-center text-xl font-bold">Sign in with Auth Dance</h1>
					{card}
					{failure !== undefined && (
						<Alert variant="destructive">
							<AlertTitle>{describeError(failure)}</AlertTitle>
						</Alert>
					)}
					<Field>
						<Button onClick={accept} disabled={pending}>
							{pending && <Loader2Icon className="animate-spin" />}
							Continue as {emailOf(tokens.tokens.access_token) ?? "your passkey account"}
						</Button>
						<Button
							variant="outline"
							onClick={async () => {
								await client.signOut();
								setAnotherAccount(true);
							}}
						>
							Use another account
						</Button>
					</Field>
					{cancel}
				</FieldGroup>
			</AuthLayout>
		);
	}

	return (
		<AuthLayout>
			<div className="flex flex-col gap-6">
				{card}
				<SignInForm title="Sign in to continue" onDone={accept} />
				{cancel}
			</div>
		</AuthLayout>
	);
}
