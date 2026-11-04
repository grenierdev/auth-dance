import { MoonIcon, SunIcon } from "lucide-react";

/** Runs before paint. Dark is the default; only a stored choice of light turns it off. */
export const themeScript = `(function(){try{var t=localStorage.getItem("theme");document.documentElement.classList.toggle("dark",t!=="light")}catch(e){}})()`;

export function ThemeToggle() {
	function toggle() {
		const dark = !document.documentElement.classList.contains("dark");
		document.documentElement.classList.toggle("dark", dark);
		try {
			localStorage.setItem("theme", dark ? "dark" : "light");
		} catch {}
	}
	return (
		<button
			type="button"
			onClick={toggle}
			aria-label="Switch between light and dark theme"
			className="grid size-8 place-items-center rounded-md text-muted transition-colors hover:bg-surface-2 hover:text-fg"
		>
			<SunIcon className="hidden size-4 dark:block" strokeWidth={1.5} />
			<MoonIcon className="size-4 dark:hidden" strokeWidth={1.5} />
		</button>
	);
}
