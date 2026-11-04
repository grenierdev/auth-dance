/** The mark: three steps on one line, the middle one taken. Drawn, so it inherits the text color. */
export function Mark({ className = "size-5" }: { className?: string }) {
	return (
		<svg viewBox="0 0 24 24" fill="none" aria-hidden="true" className={className}>
			<rect x="0.75" y="0.75" width="22.5" height="22.5" stroke="currentColor" strokeWidth="1.5" />
			<path d="M5 16.5C8 16.5 9 7.5 12 7.5S16 16.5 19 16.5" stroke="currentColor" strokeWidth="1.5" />
			<rect x="3" y="14.5" width="4" height="4" fill="currentColor" />
			<rect x="10" y="5.5" width="4" height="4" fill="currentColor" />
			<rect x="17" y="14.5" width="4" height="4" fill="currentColor" />
		</svg>
	);
}

export function Wordmark() {
	return (
		<span className="flex items-center gap-2.5 font-medium tracking-[-0.01em]">
			<Mark />
			Auth Dance
		</span>
	);
}
