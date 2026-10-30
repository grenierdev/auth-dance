import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { Loader2Icon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { AuthLayout } from "@/components/auth-layout";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { loadDemoInfo, oauth2Form } from "@/lib/demo";
import { REDIRECT_URI, takePendingAuthorization, writeNotesTokens } from "@/lib/notes";

interface CallbackSearch {
	code?: string;
	state?: string;
	iss?: string;
	error?: string;
	error_description?: string;
}

export const Route = createFileRoute("/playground/callback")({
	validateSearch: (search: Record<string, unknown>): CallbackSearch =>
		Object.fromEntries(Object.entries(search).filter(([, value]) => typeof value === "string")) as CallbackSearch,
	component: Callback,
});

/** The `redirect_uri` of Dance Notes: it checks the state and the issuer, then exchanges the code. */
function Callback() {
	const search = Route.useSearch();
	const navigate = useNavigate();
	const [failure, setFailure] = useState<string>();
	const once = useRef(false);

	useEffect(() => {
		if (once.current) {
			return;
		}
		once.current = true;
		(async () => {
			const pending = takePendingAuthorization();
			if (search.error) {
				setFailure(`${search.error}: ${search.error_description ?? ""}`);
				return;
			}
			if (!pending || pending.state !== search.state || !search.code) {
				setFailure("The state does not match the request this app started.");
				return;
			}
			// RFC 9207: the authorization server names itself, so a mix-up with another server shows.
			if (search.iss !== window.location.origin) {
				setFailure(`Unexpected issuer ${search.iss}`);
				return;
			}
			const info = await loadDemoInfo();
			const { status, body } = await oauth2Form("/oauth2/token", {
				grant_type: "authorization_code",
				code: search.code,
				redirect_uri: REDIRECT_URI,
				client_id: info.clients.notes,
				code_verifier: pending.code_verifier,
			});
			if (status !== 200) {
				setFailure(`${body.error}: ${body.error_description ?? ""}`);
				return;
			}
			writeNotesTokens(body);
			await navigate({ to: "/playground", replace: true });
		})();
	}, [search, navigate]);

	return (
		<AuthLayout>
			{failure ? (
				<Alert variant="destructive">
					<AlertTitle>Dance Notes could not sign you in</AlertTitle>
					<AlertDescription>
						<p>{failure}</p>
						<Link to="/playground" className="underline">
							Back to Dance Notes
						</Link>
					</AlertDescription>
				</Alert>
			) : (
				<div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
					<Loader2Icon className="size-4 animate-spin" /> Exchanging the code…
				</div>
			)}
		</AuthLayout>
	);
}
