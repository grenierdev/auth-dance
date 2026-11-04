import { MDXContent } from "@content-collections/mdx/react";
import { Link } from "@tanstack/react-router";
import { type ComponentProps, useRef } from "react";
import { CopyButton } from "./copy-button";

function Pre(props: ComponentProps<"pre"> & { "data-title"?: string }) {
	const ref = useRef<HTMLPreElement>(null);
	return (
		<div className="codeframe group" data-title={props["data-title"]}>
			<pre ref={ref} {...props} />
			<CopyButton
				text={() => ref.current?.textContent ?? ""}
				label="Copy code"
				className={`absolute right-1.5 bg-surface opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100 [@media(hover:none)]:opacity-100 ${props["data-title"] ? "top-1" : "top-2"}`}
			/>
		</div>
	);
}

function A({ href = "", ...props }: ComponentProps<"a">) {
	if (href.startsWith("/")) return <Link to={href} {...props} />;
	return <a href={href} {...props} />;
}

export function Mdx({ code }: { code: string }) {
	return <MDXContent code={code} components={{ pre: Pre, a: A }} />;
}
