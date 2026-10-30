import type { ReactNode } from "react";

/** The frame of the login-05 block: one narrow column in the middle of the page. */
export function AuthLayout({ children }: { children: ReactNode }) {
	return (
		<div className="flex min-h-[calc(100svh-3.5rem)] flex-col items-center justify-center gap-6 bg-background p-6 md:p-10">
			<div className="w-full max-w-sm">{children}</div>
		</div>
	);
}
