import { CheckIcon, CornerDownLeftIcon, KeyRoundIcon, MailIcon, SendIcon, SplitIcon, FingerprintIcon } from "lucide-react";
import { type CSSProperties, type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { deriveFlows, PRESETS } from "@/lib/derive";
import { type ConsoleEvent, script } from "@/lib/script";
import { Path } from "./path";
import { Window, WindowBar } from "./window";

const BEAT_MS = 760;
/** Beats the finished path stays on screen before the next one starts. */
const HOLD = 4;

function useReducedMotion() {
	const [reduced, setReduced] = useState(false);
	useEffect(() => {
		const mq = matchMedia("(prefers-reduced-motion: reduce)");
		setReduced(mq.matches);
		const on = () => setReduced(mq.matches);
		mq.addEventListener("change", on);
		return () => mq.removeEventListener("change", on);
	}, []);
	return reduced;
}

/** True while the element is on screen and the tab is visible. */
function useOnScreen<T extends HTMLElement>() {
	const ref = useRef<T>(null);
	const [on, setOn] = useState(true);
	useEffect(() => {
		const el = ref.current;
		if (!el) return;
		let visible = true;
		const sync = () => setOn(visible && !document.hidden);
		const io = new IntersectionObserver(([e]) => {
			visible = e.isIntersecting;
			sync();
		});
		io.observe(el);
		document.addEventListener("visibilitychange", sync);
		return () => {
			io.disconnect();
			document.removeEventListener("visibilitychange", sync);
		};
	}, []);
	return [ref, on] as const;
}

/**
 * The landing page's product window: a client runs each derived flow against the server, prompt by prompt. The
 * flows and their paths come from the library's own `walk`; the routes and response fields are the real ones.
 */
export function DanceConsole() {
	const [presetIndex, setPresetIndex] = useState(0);
	const [pos, setPos] = useState({ run: 0, beat: 0 });
	const [hover, setHover] = useState(false);
	const [ref, onScreen] = useOnScreen<HTMLDivElement>();
	const reduced = useReducedMotion();
	const preset = PRESETS[presetIndex];
	const flows = useMemo(() => deriveFlows(preset), [preset]);
	const runs = useMemo(() => flows.flatMap((f, fi) => f.paths.map((_, pi) => ({ fi, pi, events: script(f, pi) }))), [flows]);
	const run = runs[pos.run] ?? runs[0];
	const still = reduced || hover || !onScreen;
	const shown = reduced ? run.events.length : Math.min(pos.beat + 1, run.events.length);
	const events = run.events.slice(0, shown);
	const flow = flows[run.fi];

	useEffect(() => {
		if (still) return;
		const id = setInterval(() => {
			setPos((p) => {
				const len = (runs[p.run]?.events.length ?? 0) + HOLD;
				return p.beat + 1 >= len ? { run: (p.run + 1) % runs.length, beat: 0 } : { ...p, beat: p.beat + 1 };
			});
		}, BEAT_MS);
		return () => clearInterval(id);
	}, [still, runs]);

	function choosePreset(i: number) {
		setPresetIndex(i);
		setPos({ run: 0, beat: 0 });
	}
	function chooseFlow(fi: number) {
		const r = runs.findIndex((x) => x.fi === fi);
		if (r >= 0) setPos({ run: r, beat: 0 });
	}

	const requests = events.filter((e): e is Extract<ConsoleEvent, { kind: "request" }> => e.kind === "request");
	// The newest rows, top-down; older ones scroll away.
	const activity = events.filter((e) => e.kind !== "request").slice(-7);
	const offset = events.filter((e) => e.kind !== "request").length - activity.length;
	// How far along the path the client is: the steps whose answer has gone out.
	const answered = new Set(events.filter((e) => e.kind === "answer").map((e) => (e as { step: string }).step));
	const path = flow.paths[run.pi];
	const done = events.at(-1)?.kind === "done";
	const stepIndex = done ? path.length : path.findIndex((s) => !answered.has(s));
	const current = done ? undefined : path[stepIndex];

	return (
		<div ref={ref} className="relative">
			<Window
				className="grid h-[36rem] grid-cols-[minmax(0,1fr)] overflow-hidden md:h-[34rem] md:grid-cols-[13.5rem_minmax(0,1fr)] lg:h-[33rem] lg:grid-cols-[13.5rem_minmax(0,1fr)_21rem]"
				onMouseEnter={() => setHover(true)}
				onMouseLeave={() => setHover(false)}
				onFocus={() => setHover(true)}
				onBlur={() => setHover(false)}
				aria-label="A client running each derived flow against the server"
				role="region"
			>
				{/* Sidebar: the choreography and the flows it derives. */}
				<aside className="hidden flex-col gap-6 border-r border-line bg-bg/40 p-3 md:flex">
					<div className="flex items-center gap-2 px-2 pt-1 text-[13px] font-medium">
						<span className="grid size-5 place-items-center rounded-[5px] bg-fg text-[10px] font-semibold text-invert">A</span>
						auth.example.com
					</div>
					<Group title="Choreography">
						{PRESETS.map((p, i) => (
							<NavItem key={p.id} active={i === presetIndex} onClick={() => choosePreset(i)}>
								{p.label}
							</NavItem>
						))}
					</Group>
					<Group title="Flows">
						{flows.map((f, fi) => (
							<NavItem
								key={f.id}
								active={fi === run.fi}
								disabled={f.paths.length === 0}
								onClick={() => chooseFlow(fi)}
								trailing={f.paths.length === 0 ? "none" : f.paths.length > 1 ? `${f.paths.length} paths` : undefined}
							>
								{f.label}
							</NavItem>
						))}
					</Group>
				</aside>

				{/* The flow being performed. */}
				<section className="flex min-h-0 min-w-0 flex-col">
					<WindowBar>
						<span className="text-fg">{flow.label}</span>
						<span className="text-faint">/</span>
						<span className="truncate text-xs">Path {run.pi + 1} of {flow.paths.length}</span>
						<span className="ml-auto flex items-center gap-1.5 text-xs">
							<span aria-hidden="true" className={`size-1.5 rounded-full ${still ? "bg-line-strong" : "live bg-accent"}`} />
							{reduced ? "static" : still ? "paused" : "live"}
						</span>
					</WindowBar>
					<div className="border-b border-line px-5 py-4">
						<p className="font-mono text-[12.5px] leading-relaxed break-words text-muted">
							<CodeLine code={preset.code} active={current} />
						</p>
						<div className="mt-3 flex flex-wrap items-center gap-y-2">
							<Path steps={path} labels={flow.labels} state={done ? "done" : "performing"} beatStep={stepIndex} outcome={flow.outcome} />
						</div>
					</div>
					{/* Mobile: the flows as a row of tabs. */}
					<div className="flex gap-1 overflow-x-auto border-b border-line px-3 py-2 md:hidden">
						{flows.map((f, fi) => (
							<button
								key={f.id}
								type="button"
								disabled={f.paths.length === 0}
								onClick={() => chooseFlow(fi)}
								className={`shrink-0 rounded-md px-2.5 py-1 text-xs transition-colors disabled:opacity-40 ${fi === run.fi ? "bg-surface-2 text-fg" : "text-muted hover:text-fg"}`}
							>
								{f.label}
							</button>
						))}
					</div>
					<ol className="flex min-h-0 flex-1 flex-col gap-3 overflow-hidden px-5 pt-5 pb-16" aria-live="off">
						{activity.map((e, i) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: the list only grows within one run
							<Activity key={`${pos.run}-${offset + i}`} event={e} />
						))}
					</ol>
					{/* Below lg the request log folds into a strip under the loop: the last two requests. */}
					<ol className="border-t border-line lg:hidden">
						{requests.slice(-2).map((r, i) => (
							<li key={`${pos.run}-${requests.length - 2 + i}`} className="row-in flex items-center gap-2 border-b border-line px-4 py-2 font-mono text-[11.5px] last:border-b-0">
								<span className="rounded-[4px] bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">POST</span>
								<span className="truncate text-fg">{r.route}</span>
								<span className="ml-auto text-faint">200</span>
								<span className="w-9 text-right text-faint">{r.ms}ms</span>
							</li>
						))}
					</ol>
				</section>

				{/* The wire: every request the client sent. */}
				<aside className="hidden min-h-0 flex-col border-l border-line bg-bg/40 lg:flex">
					<WindowBar>
						<span className="text-fg">Requests</span>
						<span className="ml-auto font-mono text-xs">{requests.length}</span>
					</WindowBar>
					<ol className="flex flex-col">
						{requests.map((r, i) => (
							// biome-ignore lint/suspicious/noArrayIndexKey: the list only grows within one run
							<li key={`${pos.run}-${i}`} className="row-in border-b border-line px-4 py-2.5 font-mono text-[11.5px]">
								<div className="flex items-center gap-2">
									<span className="rounded-[4px] bg-surface-2 px-1.5 py-0.5 text-[10px] text-muted">POST</span>
									<span className="truncate text-fg">{r.route}</span>
									<span className="ml-auto text-faint">200</span>
									<span className="w-9 text-right text-faint">{r.ms}ms</span>
								</div>
								<p className="mt-1.5 truncate text-[11px] text-faint">{r.body}</p>
							</li>
						))}
					</ol>
				</aside>
			</Window>
			{/* The window runs on into the page, Linear style. */}
			<div aria-hidden="true" className="pointer-events-none absolute inset-x-0 bottom-0 hidden h-14 rounded-b-xl bg-linear-to-b from-transparent to-bg lg:block" />
			{/* The inspector: the last response, on a sheet raised over the log and the loop. */}
			{requests.length > 0 && (
				<div className="sheet absolute right-5 bottom-10 z-10 hidden w-[25rem] lg:block xl:-right-6">
					<div className="flex h-10 items-center gap-2 border-b border-line px-4 text-[13px]">
						<span className="text-fg">Response</span>
						<span className="font-mono text-xs text-muted">{requests.at(-1)?.route}</span>
						<span className="ml-auto text-xs text-faint">200 OK</span>
					</div>
					<pre key={`${pos.run}-${requests.length}`} className="row-in line-clamp-[7] p-4 font-mono text-[11.5px] leading-[1.65] break-all whitespace-pre-wrap">
						<Json text={requests.at(-1)?.response ?? ""} />
					</pre>
				</div>
			)}
			<p className="sr-only">
				The window shows a client performing the sign-in, the sign-up and each recovery of the choreography {preset.code}, one prompt at a time.
			</p>
		</div>
	);
}

function Group({ title, children }: { title: string; children: ReactNode }) {
	return (
		<div>
			<p className="mb-1 px-2 text-[11.5px] font-medium text-faint">{title}</p>
			<ul className="flex flex-col gap-px">{children}</ul>
		</div>
	);
}

function NavItem({ active, disabled, onClick, trailing, children }: { active: boolean; disabled?: boolean; onClick: () => void; trailing?: string; children: ReactNode }) {
	return (
		<li>
			<button
				type="button"
				disabled={disabled}
				onClick={onClick}
				aria-current={active || undefined}
				className={`flex h-7 w-full items-center gap-2 rounded-md px-2 text-left text-[13px] transition-colors disabled:cursor-default disabled:opacity-45 ${active ? "bg-surface-2 text-fg" : "text-muted hover:bg-surface-2/60 hover:text-fg"}`}
			>
				<span className="truncate">{children}</span>
				{trailing && <span className="ml-auto shrink-0 text-[11px] text-faint">{trailing}</span>}
			</button>
		</li>
	);
}

const ICON: Record<string, typeof MailIcon> = { email: MailIcon, password: KeyRoundIcon, otp: SendIcon, webauthn: FingerprintIcon };

function Activity({ event: e }: { event: ConsoleEvent }) {
	if (e.kind === "prompt") {
		const Icon = e.choice ? SplitIcon : (ICON[e.type] ?? KeyRoundIcon);
		return (
			<li className="row-in flex items-start gap-3 text-[13px]">
				<span className="mt-px grid size-6 shrink-0 place-items-center rounded-full border border-line bg-surface-2 text-muted">
					<Icon className="size-3.5" strokeWidth={1.75} />
				</span>
				<p className="pt-0.5 leading-relaxed text-muted">
					{e.choice ? (
						<>
							The server asks for a <span className="text-fg">choice</span>:{" "}
							{e.choice.map((c, i) => (
								<span key={c}>
									{i > 0 && " or "}
									<code className={`rounded-[4px] px-1 font-mono text-[12px] ${c === e.step ? "bg-accent-wash text-fg" : "bg-surface-2"}`}>{c}</code>
								</span>
							))}
						</>
					) : (
						<>
							The server asks for <code className="rounded-[4px] bg-surface-2 px-1 font-mono text-[12px] text-fg">{e.step}</code>
							{e.sendable && <span className="text-faint"> · sent by the server first</span>}
						</>
					)}
				</p>
			</li>
		);
	}
	if (e.kind === "answer") {
		const shown = e.secret ? "•".repeat(e.value.length) : e.value;
		return (
			<li className="row-in ml-9 flex items-center gap-3 rounded-lg border border-line bg-bg/50 px-3 py-2 font-mono text-[12.5px]">
				<span className="type-in overflow-hidden whitespace-nowrap text-fg" style={{ "--chars": shown.length } as CSSProperties}>
					{shown}
				</span>
				<CornerDownLeftIcon aria-hidden="true" className="ml-auto size-3.5 shrink-0 text-faint" strokeWidth={1.75} />
			</li>
		);
	}
	if (e.kind === "done") {
		return (
			<li className="row-in flex items-center gap-3 text-[13px]">
				<span className="grid size-6 shrink-0 place-items-center rounded-full bg-accent text-accent-fg">
					<CheckIcon className="size-3.5" strokeWidth={2.25} />
				</span>
				{e.tokens ? (
					<p className="text-fg">
						Signed in. The server hands back an <code className="font-mono text-[12px] text-accent-text">at+jwt</code> and an{" "}
						<code className="font-mono text-[12px] text-accent-text">rt+jwt</code>.
					</p>
				) : (
					<p className="text-fg">Recovered. The {e.outcome} is registered, and every session of the identity ends.</p>
				)}
			</li>
		);
	}
	return null;
}

/** The choreography line, with the step the client is on lit. */
function CodeLine({ code, active }: { code: string; active?: string }) {
	return (
		<>
			{code.split(/("[^"]+")/).map((part, i) => {
				const name = /^"(.+)"$/.exec(part)?.[1];
				// biome-ignore lint/suspicious/noArrayIndexKey: a static split of one line
				if (!name) return <span key={i}>{part}</span>;
				return (
					// biome-ignore lint/suspicious/noArrayIndexKey: a static split of one line
					<span key={i} className={`transition-colors duration-300 ${active === name ? "text-accent-text" : "text-fg"}`}>
						{part}
					</span>
				);
			})}
		</>
	);
}

/** A response body with its keys dimmed, so the values read first. */
function Json({ text }: { text: string }) {
	return (
		<>
			{text.split(/("[^"]*"(?=\s*:))/).map((part, i) =>
				// biome-ignore lint/suspicious/noArrayIndexKey: a static split of one string
				/^"[^"]*"$/.test(part) ? <span key={i} className="text-muted">{part}</span> : <span key={i} className="text-fg">{part}</span>,
			)}
		</>
	);
}
