/**
 * Three line drawings for the statement row: the tree a developer declares, the flows the library derives from it,
 * and the recovery path around a lost step. Drawn in the hairline colours, with the accent on what moves.
 */

const T = "font-mono text-[10px] fill-(--muted)";
const NODE = "fill-(--surface-2) stroke-(--line-strong)";

function Node({ x, y, w, label, accent }: { x: number; y: number; w: number; label: string; accent?: boolean }) {
	return (
		<g>
			<rect x={x - w / 2} y={y - 11} width={w} height={22} rx={5} className={accent ? "fill-(--accent-wash) stroke-(--accent)" : NODE} />
			<text x={x} y={y + 3.5} textAnchor="middle" className={accent ? "font-mono text-[10px] fill-(--fg)" : T}>
				{label}
			</text>
		</g>
	);
}

export function FigureDeclare() {
	return (
		<svg viewBox="0 0 280 180" className="h-auto w-full" role="img" aria-label="The choreography as a tree: a choice between a sequence of email and password, and passkey">
			<g className="stroke-(--line-strong)" fill="none">
				<path d="M140 42 V60 H80 V78 M140 60 H210 V78" />
				<path d="M80 100 V114 H48 V128 M80 114 H112 V128" />
			</g>
			<Node x={140} y={32} w={64} label="choice" accent />
			<Node x={80} y={90} w={76} label="sequence" />
			<Node x={210} y={90} w={64} label="passkey" />
			<Node x={48} y={138} w={52} label="email" />
			<Node x={112} y={138} w={64} label="password" />
		</svg>
	);
}

export function FigureDerive() {
	const flows = ["sign-in", "sign-up", "enroll", "rotate", "recover", "delete"];
	return (
		<svg viewBox="0 0 280 180" className="h-auto w-full" role="img" aria-label="One tree on the left, six flows fanning out of it on the right">
			<g className="stroke-(--line-strong)" fill="none">
				{flows.map((f, i) => {
					const y = 24 + i * 27;
					return <path key={f} d={`M86 90 C 130 90, 130 ${y}, 172 ${y}`} className={i === 0 ? "stroke-(--accent)" : ""} />;
				})}
			</g>
			<Node x={52} y={90} w={68} label="the tree" accent />
			{flows.map((f, i) => (
				<Node key={f} x={212} y={24 + i * 27} w={80} label={f} />
			))}
		</svg>
	);
}

export function FigureRecover() {
	return (
		<svg viewBox="0 0 280 180" className="h-auto w-full" role="img" aria-label="A sign-in path through email and password, and the recovery that goes around the lost password with a one-time code">
			<g fill="none">
				<path d="M62 64 H80" className="stroke-(--line-strong)" />
				<path d="M144 64 H160" className="stroke-(--line-strong)" strokeDasharray="3 3" />
				<path d="M36 75 C 36 116, 92 124, 126 124" className="stroke-(--accent)" />
				<path d="M174 124 C 212 124, 222 104, 222 75" className="stroke-(--accent)" />
			</g>
			<Node x={36} y={64} w={52} label="email" />
			<g opacity={0.5}>
				<rect x={80} y={53} width={64} height={22} rx={5} className="fill-none stroke-(--line-strong)" strokeDasharray="3 3" />
				<text x={112} y={67.5} textAnchor="middle" className={T}>
					password
				</text>
			</g>
			<text x={112} y={40} textAnchor="middle" className="font-mono text-[9.5px] fill-(--faint)">
				lost
			</text>
			<Node x={150} y={124} w={48} label="code" accent />
			<Node x={222} y={64} w={92} label="new password" accent />
		</svg>
	);
}
