import { CheckIcon, CopyIcon } from "lucide-react";
import { useState } from "react";

export function CopyButton({ text, label = "Copy", className = "" }: { text: string | (() => string); label?: string; className?: string }) {
	const [done, setDone] = useState(false);
	async function copy() {
		try {
			await navigator.clipboard.writeText(typeof text === "function" ? text() : text);
			setDone(true);
			setTimeout(() => setDone(false), 1600);
		} catch {}
	}
	return (
		<button
			type="button"
			onClick={copy}
			aria-label={done ? "Copied" : label}
			className={`grid size-7 place-items-center rounded-md text-faint transition-colors hover:bg-surface-2 hover:text-fg ${className}`}
		>
			{done ? <CheckIcon className="size-3.5" strokeWidth={2} /> : <CopyIcon className="size-3.5" strokeWidth={1.5} />}
		</button>
	);
}

/** The install command, the primary action of the site. A copy marks the box with tape and says what comes next. */
export function InstallCommand() {
	const cmd = "npm install auth-dance";
	const [copied, setCopied] = useState(false);
	async function copy() {
		try {
			await navigator.clipboard.writeText(cmd);
			setCopied(true);
			setTimeout(() => setCopied(false), 2200);
		} catch {}
	}
	return (
		<button
			type="button"
			onClick={copy}
			aria-label={copied ? "Copied the install command" : "Copy the install command"}
			className={`group flex h-11 w-full items-center justify-between gap-4 rounded-lg border bg-surface pr-3 pl-4 text-left font-mono text-[13px] transition-colors duration-300 ${copied ? "border-accent" : "border-line-strong hover:border-muted"}`}
		>
			<span className="whitespace-nowrap">
				<span className="text-accent-text select-none">$ </span>
				{cmd}
			</span>
			<span className={`flex items-center gap-1.5 text-xs transition-colors ${copied ? "text-accent-text" : "text-faint group-hover:text-fg"}`} aria-live="polite">
				{copied ? <CheckIcon className="size-3.5" strokeWidth={2} /> : <CopyIcon className="size-3.5" strokeWidth={1.5} />}
				<span className="hidden sm:inline">{copied ? "Copied" : "Copy"}</span>
			</span>
		</button>
	);
}
