import { Fragment, useMemo, useState } from "react";
import { COMPOSABLE, type Composable, compose, deriveFlows } from "@/lib/derive";
import { Path } from "./path";
import { Window, WindowBar } from "./window";

const HINT: Record<Composable | "passkey", string> = {
	password: "a secret the owner knows",
	otp: "a one-time code by mail or SMS",
	totp: "a code from an authenticator app",
	passkey: "a WebAuthn credential, its own path",
};

/**
 * The landing page's playground: the visitor toggles steps, the composer writes the choreography line, and every flow
 * re-derives from the library's own `walk`. A path that proves nothing shows the error the constructor raises.
 */
export function Composer() {
	const [steps, setSteps] = useState<Composable[]>(["password"]);
	const [passkey, setPasskey] = useState(true);
	const [fresh, setFresh] = useState<string | undefined>();
	const preset = useMemo(() => compose({ steps, passkey }), [steps, passkey]);
	const flows = useMemo(() => (preset.invalid ? [] : deriveFlows(preset)), [preset]);

	function toggle(name: Composable | "passkey") {
		const on = name === "passkey" ? passkey : steps.includes(name);
		setFresh(on ? undefined : name);
		if (name === "passkey") setPasskey(!on);
		else setSteps(on ? steps.filter((s) => s !== name) : [...steps, name]);
	}

	return (
		<Window className="overflow-hidden">
			<WindowBar>
				<span className="text-fg">Composer</span>
				<span className="text-faint">/</span>
				<span className="font-mono text-xs">server.ts</span>
			</WindowBar>
			<div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3 sm:px-5" role="group" aria-label="Steps of the choreography">
				<StepToggle name="email" pressed disabled hint="the identification, the step that names the owner" />
				{COMPOSABLE.map((s) => (
					<StepToggle key={s} name={s} pressed={steps.includes(s)} onClick={() => toggle(s)} hint={HINT[s]} />
				))}
				<span className="px-1 text-xs text-faint">or</span>
				<StepToggle name="passkey" pressed={passkey} onClick={() => toggle("passkey")} hint={HINT.passkey} />
			</div>

			<div className="border-b border-line bg-bg/40 px-4 py-4 sm:px-5">
				<p className="mb-2 text-xs text-faint">Choreography</p>
				<code key={preset.code} className="code-in block min-h-[2lh] font-mono text-[13px] leading-relaxed break-words sm:min-h-0 sm:text-sm">
					<Tokens code={preset.code} fresh={fresh} />
				</code>
			</div>

			<div>
				{preset.invalid ? (
					<div className="shake px-4 py-6 sm:px-5">
						<p className="font-mono text-xs text-accent-text">InvalidChoreographyError</p>
						<p className="mt-2 max-w-md text-sm leading-relaxed">
							The path <code className="font-mono text-[0.92em]">{preset.invalid.join(" → ")}</code> proves nothing. An address names an
							identity, it does not prove control of it. The server refuses to start.
						</p>
						<p className="mt-3 text-sm text-muted">Add a step that proves control.</p>
					</div>
				) : (
					<ol className="divide-y divide-line">
						{flows.map((f) => (
							<li key={f.id} className="grid gap-x-4 gap-y-2 px-4 py-3.5 sm:grid-cols-[9.5rem_1fr] sm:px-5">
								<div className="flex items-baseline justify-between gap-3 sm:block">
									<p className="text-sm font-medium">{f.label}</p>
									<p className="text-xs text-faint sm:mt-0.5">{f.note}</p>
								</div>
								<div className="flex flex-wrap items-center gap-x-3 gap-y-2">
									{f.paths.length === 0 ? (
										<p className="text-xs leading-relaxed text-muted">Not recoverable. The owner signs in another way and enrolls it again.</p>
									) : (
										f.paths.map((p, i) => (
											<Fragment key={p.join()}>
												{i > 0 && <span className="text-xs text-faint">or</span>}
												<Path steps={p} labels={f.labels} state="done" beatStep={-1} fresh={fresh} outcome={i === f.paths.length - 1 ? f.outcome : undefined} />
											</Fragment>
										))
									)}
								</div>
							</li>
						))}
					</ol>
				)}
			</div>

			<div className="flex h-10 items-center justify-between gap-4 border-t border-line px-4 text-xs text-faint sm:px-5">
				<span aria-live="polite">{preset.invalid ? "0 flows · refused at startup" : `${flows.length} flows from one line`}</span>
				<button
					type="button"
					onClick={() => {
						setSteps(["password"]);
						setPasskey(true);
						setFresh(undefined);
					}}
					className="transition-colors hover:text-fg"
				>
					Reset
				</button>
			</div>
		</Window>
	);
}

function StepToggle({ name, pressed, disabled, onClick, hint }: { name: string; pressed: boolean; disabled?: boolean; onClick?: () => void; hint: string }) {
	return (
		<button
			type="button"
			aria-pressed={pressed}
			disabled={disabled}
			onClick={onClick}
			title={hint}
			className={`group inline-flex h-8 items-center gap-2 rounded-md border px-2.5 font-mono text-xs transition-[background-color,color,border-color,transform] duration-200 ease-(--ease-out-expo) active:scale-[0.96] disabled:cursor-default ${
				pressed
					? disabled
						? "border-line-strong bg-surface-2 text-fg"
						: "border-accent bg-accent-wash text-fg hover:bg-accent hover:text-accent-fg"
					: "border-dashed border-line-strong text-faint hover:border-muted hover:text-fg"
			}`}
		>
			<span aria-hidden="true" className={`grid size-3 place-items-center rounded-[3px] border text-[9px] leading-none transition-colors ${pressed ? (disabled ? "border-muted bg-muted" : "border-accent bg-accent") : "border-line-strong"}`}>
				{pressed && <span className={`size-1 rounded-[1px] ${disabled ? "bg-bg" : "bg-accent-fg"}`} />}
			</span>
			{name}
		</button>
	);
}

/** The composed line, with the step the visitor just added washed in the accent for a moment. */
function Tokens({ code, fresh }: { code: string; fresh?: string }) {
	return (
		<>
			{code.split(/("[^"]+")/).map((part, i) => {
				const name = /^"(.+)"$/.exec(part)?.[1];
				// biome-ignore lint/suspicious/noArrayIndexKey: a static split of one line
				if (!name) return <span key={i} className="text-muted">{part}</span>;
				return (
					// biome-ignore lint/suspicious/noArrayIndexKey: a static split of one line
					<span key={i} className={`text-fg ${name === fresh ? "token-in" : ""}`}>
						{part}
					</span>
				);
			})}
		</>
	);
}
