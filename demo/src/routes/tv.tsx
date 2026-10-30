import { createFileRoute } from "@tanstack/react-router";
import { ExternalLinkIcon, MonitorIcon, PowerIcon } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/button";
import { decodeJwt } from "@/lib/auth";
import { oauth2Form, useDemoInfo } from "@/lib/demo";

export const Route = createFileRoute("/tv")({ component: Tv });

interface DeviceAuthorization {
	device_code: string;
	user_code: string;
	verification_uri: string;
	verification_uri_complete: string;
	expires_in: number;
	interval: number;
}

type Screen =
	| { kind: "off" }
	| { kind: "code"; authorization: DeviceAuthorization; expiresAt: number; polls: number; last?: string }
	| { kind: "signed-in"; claims: Record<string, unknown> }
	| { kind: "failed"; error: string };

/**
 * Dance TV: a device with no keyboard. It asks `/oauth2/device_authorization` for a user code, shows it, and polls
 * `/oauth2/token` until the owner approves on another screen (RFC 8628).
 */
function Tv() {
	const info = useDemoInfo();
	const [screen, setScreen] = useState<Screen>({ kind: "off" });
	const [now, setNow] = useState(Date.now());
	const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

	useEffect(() => {
		const tick = setInterval(() => setNow(Date.now()), 1000);
		return () => {
			clearInterval(tick);
			clearTimeout(timer.current);
		};
	}, []);

	async function start() {
		clearTimeout(timer.current);
		const { status, body } = await oauth2Form("/oauth2/device_authorization", { client_id: info!.clients.tv, scope: "profile" });
		if (status !== 200) {
			setScreen({ kind: "failed", error: `${body.error}: ${body.error_description ?? ""}` });
			return;
		}
		const authorization = body as DeviceAuthorization;
		setScreen({ kind: "code", authorization, expiresAt: Date.now() + authorization.expires_in * 1000, polls: 0 });
		poll(authorization, authorization.interval);
	}

	function poll(authorization: DeviceAuthorization, interval: number) {
		timer.current = setTimeout(async () => {
			const { status, body } = await oauth2Form("/oauth2/token", {
				grant_type: "urn:ietf:params:oauth:grant-type:device_code",
				device_code: authorization.device_code,
				client_id: info!.clients.tv,
			});
			if (status === 200) {
				setScreen({ kind: "signed-in", claims: decodeJwt(body.access_token) });
				return;
			}
			if (body.error === "authorization_pending" || body.error === "slow_down") {
				setScreen((current) => (current.kind === "code" ? { ...current, polls: current.polls + 1, last: body.error } : current));
				// RFC 8628 §3.5: `slow_down` adds five seconds to the interval, for good.
				poll(authorization, body.error === "slow_down" ? interval + 5 : interval);
				return;
			}
			setScreen({ kind: "failed", error: `${body.error}: ${body.error_description ?? ""}` });
		}, interval * 1000);
	}

	function powerOff() {
		clearTimeout(timer.current);
		setScreen({ kind: "off" });
	}

	return (
		<main className="mx-auto flex max-w-4xl flex-col gap-6 px-4 py-10">
			<div>
				<h1 className="text-2xl font-bold tracking-tight">Dance TV</h1>
				<p className="text-sm text-muted-foreground">
					A pretend TV. It cannot show a login page, so it shows a code to type on another screen: the device authorization grant.
				</p>
			</div>

			<div className="rounded-3xl bg-neutral-800 p-4 shadow-2xl">
				<div className="flex aspect-video flex-col items-center justify-center gap-6 rounded-2xl bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 p-6 text-center text-white">
					{screen.kind === "off" && (
						<>
							<MonitorIcon className="size-12 opacity-60" />
							<p className="text-lg opacity-80">Sign in to watch your dances</p>
							<Button size="lg" variant="secondary" disabled={!info} onClick={start}>
								Sign in
							</Button>
						</>
					)}
					{screen.kind === "code" && (
						<>
							<p className="text-sm opacity-80 sm:text-lg">On your phone or computer, go to</p>
							<a
								href={screen.authorization.verification_uri}
								target="_blank"
								rel="noreferrer"
								className="font-mono text-base underline underline-offset-4 sm:text-2xl"
							>
								{screen.authorization.verification_uri}
							</a>
							<p className="text-sm opacity-80 sm:text-lg">and enter</p>
							<div className="font-mono text-4xl font-bold tracking-[0.25em] sm:text-6xl">{screen.authorization.user_code}</div>
							<div className="flex flex-wrap items-center justify-center gap-3 text-xs opacity-70">
								<span>Expires in {Math.max(0, Math.round((screen.expiresAt - now) / 1000))} s</span>
								<span>·</span>
								<span>
									Polled {screen.polls} times{screen.last ? `: ${screen.last}` : ""}
								</span>
							</div>
						</>
					)}
					{screen.kind === "signed-in" && (
						<>
							<p className="text-3xl font-bold">Welcome back</p>
							<p className="text-lg opacity-80">{String(screen.claims.email ?? screen.claims.sub)}</p>
							<p className="max-w-md text-xs opacity-60">
								The TV holds an access token for <code>{String(screen.claims.client_id)}</code> with the scope{" "}
								<code>{String(screen.claims.scope)}</code>.
							</p>
						</>
					)}
					{screen.kind === "failed" && (
						<>
							<p className="text-2xl font-bold">Sign-in failed</p>
							<p className="opacity-80">{screen.error}</p>
							<Button variant="secondary" onClick={start}>
								Try again
							</Button>
						</>
					)}
				</div>
				<div className="flex justify-center pt-3">
					<Button size="icon-sm" variant="ghost" className="text-neutral-400 hover:text-white" aria-label="Power off" onClick={powerOff}>
						<PowerIcon />
					</Button>
				</div>
			</div>

			{screen.kind === "code" && (
				<Button
					variant="outline"
					className="self-center"
					onClick={() => window.open(screen.authorization.verification_uri_complete, "_blank")}
				>
					<ExternalLinkIcon /> Open the link with the code filled in
				</Button>
			)}
		</main>
	);
}
