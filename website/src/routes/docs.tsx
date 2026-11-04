import { createFileRoute, Outlet, useRouterState } from "@tanstack/react-router";
import { MenuIcon, XIcon } from "lucide-react";
import { useEffect, useState } from "react";
import { DocsNav } from "@/components/docs-sidebar";

export const Route = createFileRoute("/docs")({ component: DocsLayout });

function DocsLayout() {
	const [open, setOpen] = useState(false);
	const path = useRouterState({ select: (s) => s.location.pathname });
	useEffect(() => setOpen(false), [path]);

	return (
		<div className="frame grid lg:grid-cols-[15.5rem_minmax(0,1fr)]">
			<aside className="hidden border-r border-line lg:block">
				<div className="sticky top-16 max-h-[calc(100svh-4rem)] overflow-y-auto px-4 py-10">
					<DocsNav />
				</div>
			</aside>

			<div className="sticky top-16 z-20 border-b border-line bg-bg/85 backdrop-blur-xl lg:hidden">
				<button
					type="button"
					aria-expanded={open}
					aria-controls="docs-mobile-nav"
					onClick={() => setOpen((o) => !o)}
					className="flex h-11 w-full items-center gap-2 px-4 text-sm text-muted sm:px-6"
				>
					{open ? <XIcon className="size-4" strokeWidth={1.5} /> : <MenuIcon className="size-4" strokeWidth={1.5} />}
					Menu
				</button>
				{open && (
					<div id="docs-mobile-nav" className="max-h-[70svh] overflow-y-auto border-t border-line px-4 py-6 sm:px-6">
						<DocsNav onNavigate={() => setOpen(false)} />
					</div>
				)}
			</div>

			<Outlet />
		</div>
	);
}
