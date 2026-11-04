import type { ComponentProps } from "react";

/** The app window every product view sits in: a raised panel with a 12px radius, a hairline and a top highlight. */
export function Window({ className = "", ...props }: ComponentProps<"div">) {
	return <div {...props} className={`window ${className}`} />;
}

/** A window's title bar: a 44px strip with a hairline under it. */
export function WindowBar({ className = "", ...props }: ComponentProps<"div">) {
	return <div {...props} className={`flex h-11 items-center gap-3 border-b border-line px-4 text-[13px] text-muted ${className}`} />;
}
