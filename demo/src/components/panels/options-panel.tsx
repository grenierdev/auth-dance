/**
 * @module
 *
 * The body of the options slideout: the choreography, the durations, and whether a rebuild seeds an identity. The panel
 * edits a local draft and commits nothing until Apply. A rebuild loses every identity, session and message.
 */

import { useMemo, useState } from "react";
import { TriangleAlertIcon } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Field, FieldDescription, FieldGroup, FieldLabel, FieldLegend, FieldSet, FieldTitle } from "@/components/ui/field.tsx";
import { Input } from "@/components/ui/input.tsx";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select.tsx";
import { Switch } from "@/components/ui/switch.tsx";
import { Textarea } from "@/components/ui/textarea.tsx";
import { type Config, DEFAULT_DURATIONS, DURATION_FIELDS, PRESETS, useDance, useDanceActions } from "@/lib/dance/index.ts";
import { resolvedTree } from "@/lib/format.ts";
import { cn } from "@/lib/utils.ts";

/** The label and value of every preset, which is what `SelectValue` reads. */
const PRESET_ITEMS = PRESETS.map((preset) => ({ label: preset.label, value: preset.id }));

/** The edit in progress. It mirrors a config, except that every duration is the text of its input. */
interface Draft {
	preset: string;
	/** The custom tree, as JSON. It survives a trip through another preset. */
	custom: string;
	/** The text of the twelve duration inputs, keyed by duration name. */
	durations: Record<string, string>;
	/** Whether a rebuild seeds the John Doe identity again. */
	seed: boolean;
}

/** Reads a config into the draft the inputs edit. */
function toDraft(config: Config): Draft {
	const durations: Record<string, string> = {};
	for (const field of DURATION_FIELDS) {
		durations[field.key] = String(config.durations[field.key]);
	}
	return { preset: config.preset, custom: config.custom, durations, seed: config.seed };
}

/** Reads the draft back into a config. Anything that is not a whole number of seconds above zero takes the default. */
function toConfig(draft: Draft): Config {
	const durations = { ...DEFAULT_DURATIONS };
	for (const field of DURATION_FIELDS) {
		const read = Number(draft.durations[field.key]);
		durations[field.key] = Number.isFinite(read) && read > 0 ? Math.floor(read) : DEFAULT_DURATIONS[field.key];
	}
	return { preset: draft.preset, custom: draft.custom, durations, seed: draft.seed };
}

/** What the options slideout needs from whoever opened it. */
export interface OptionsPanelProps {
	/** Called once the draft is on its way to the store, so the slideout can close. */
	onApplied: () => void;
}

/** The options slideout, from the warning at the top to the two buttons at the bottom. */
export function OptionsPanel({ onApplied }: OptionsPanelProps) {
	const { config, busy } = useDance();
	const { applyConfig, restoreDefaults } = useDanceActions();

	// The draft follows the config whenever the store hands out a new one: the first load, an apply, a restore.
	const [source, setSource] = useState(config);
	const [draft, setDraft] = useState(() => toDraft(config));
	if (source !== config) {
		setSource(config);
		setDraft(toDraft(config));
	}

	const resolved = useMemo(() => resolvedTree(toConfig(draft)), [draft]);

	const hint = PRESETS.find((preset) => preset.id === draft.preset)?.hint ?? "";

	const apply = (): void => {
		void applyConfig(toConfig(draft));
		if (resolved.ok) {
			onApplied();
		}
	};

	return (
		<div className="flex min-h-0 flex-1 flex-col">
			<div className="flex-1 overflow-y-auto px-6 pb-6">
				<Alert variant="destructive" className="mb-6 border-destructive/40 bg-destructive/5">
					<TriangleAlertIcon />
					<AlertTitle>Applying rebuilds the library</AlertTitle>
					<AlertDescription>Every identity, session and message of the running one is lost.</AlertDescription>
				</Alert>

				<FieldGroup>
					<FieldSet>
						<FieldLegend variant="label">Choreography</FieldLegend>

						<Field>
							<FieldLabel htmlFor="options-preset">Preset</FieldLabel>
							<Select
								items={PRESET_ITEMS}
								value={draft.preset}
								onValueChange={(value) => setDraft((current) => ({ ...current, preset: value ?? current.preset }))}
							>
								<SelectTrigger id="options-preset" className="w-full">
									<SelectValue />
								</SelectTrigger>
								<SelectContent>
									{PRESETS.map((preset) => (
										<SelectItem key={preset.id} value={preset.id}>
											{preset.label}
										</SelectItem>
									))}
								</SelectContent>
							</Select>
							<FieldDescription className="font-mono text-xs">{hint}</FieldDescription>
						</Field>

						{draft.preset === "custom" && (
							<Field>
								<FieldLabel htmlFor="options-custom">Custom tree</FieldLabel>
								<Textarea
									id="options-custom"
									spellCheck={false}
									className="min-h-48 font-mono text-xs"
									value={draft.custom}
									onChange={(event) => setDraft((current) => ({ ...current, custom: event.target.value }))}
								/>
								<FieldDescription>
									A component node names a component of the instance. A choice node forks, a sequence node runs its children in order.
								</FieldDescription>
							</Field>
						)}

						<Field>
							<FieldTitle>Resolves to</FieldTitle>
							<pre
								className={cn(
									"overflow-x-auto rounded-2xl bg-muted p-3 font-mono text-xs leading-relaxed",
									!resolved.ok && "text-destructive",
								)}
							>
								{resolved.text}
							</pre>
						</Field>
					</FieldSet>

					<FieldSet>
						<FieldLegend variant="label">Durations, in seconds</FieldLegend>
						<div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
							{DURATION_FIELDS.map((field) => (
								<Field key={field.key}>
									<FieldLabel htmlFor={`duration-${field.key}`} className="font-mono text-xs">
										{field.key}
									</FieldLabel>
									<Input
										id={`duration-${field.key}`}
										type="number"
										min={1}
										step={1}
										inputMode="numeric"
										value={draft.durations[field.key]}
										onChange={(event) =>
											setDraft((current) => ({
												...current,
												durations: { ...current.durations, [field.key]: event.target.value },
											}))}
									/>
									<FieldDescription className="text-xs">{field.hint}</FieldDescription>
								</Field>
							))}
						</div>
					</FieldSet>

					<FieldSet>
						<FieldLegend variant="label">Demo data</FieldLegend>
						<Field orientation="horizontal">
							<Switch
								id="options-seed"
								checked={draft.seed}
								onCheckedChange={(checked) => setDraft((current) => ({ ...current, seed: checked }))}
							/>
							<FieldLabel htmlFor="options-seed">Seed the John Doe identity on every rebuild</FieldLabel>
						</Field>
					</FieldSet>
				</FieldGroup>
			</div>

			<div className="mt-auto flex flex-wrap gap-2 border-t px-6 py-4">
				<Button type="button" disabled={busy} onClick={apply}>
					Apply and restart
				</Button>
				<Button type="button" variant="ghost" disabled={busy} onClick={() => void restoreDefaults()}>
					Restore defaults
				</Button>
			</div>
		</div>
	);
}
