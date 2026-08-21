import { Button, SegmentedControl, Select } from "@flanksource/clicky-ui/components";
import { describeSelection, PROFILE_NAME } from "./DiscoveryProfiles";
import type { DiscoveryProfileState } from "./DiscoveryProfiles";
import { TemplateSummary } from "./TemplatePreview";
import type { Engine, Profile, TemplatePreview } from "./types";

type Scope = "selected" | "all";

type Selection = {
  allowAllTargets: boolean;
  scope: Scope;
  selectedCount: number;
  rowCount: number;
  targetId: string;
  onScopeChange: (scope: Scope) => void;
};

type Scanner = {
  engines: Engine[];
  engineName: string;
  selectedEngine: Engine | null;
  profiles: Profile[];
  profileName: string;
  editableProfile: boolean;
  profileEdits?: Record<string, unknown>;
  preview: TemplatePreview | null;
  previewError: string | null;
  previewLoading: boolean;
  newProfileName: string;
  nameTaken: boolean;
  nameable: boolean;
  keeping: boolean;
  onChooseEngine: (name: string) => void;
  onChooseProfile: (name: string) => void;
  onNewProfileName: (name: string) => void;
  onKeepAs: () => void;
};

type Discovery = {
  profiles: DiscoveryProfileState;
  editing: boolean;
  onEditingChange: (editing: boolean) => void;
};

type Action = {
  discoveryOnly: boolean;
  discovering: boolean;
  scanActive: boolean;
  starting: boolean;
  catalogLoaded: boolean;
  targetCount: number;
  targetNoun: string;
  needsConfirm: boolean;
  confirmed: boolean;
  onStart: () => void;
  onStop: () => void;
};

type Confirmation = {
  targetIds: string[];
  confirmed: boolean;
  onConfirmedChange: (confirmed: boolean) => void;
};

type Props = {
  selection: Selection;
  scanner?: Scanner;
  discovery: Discovery;
  action: Action;
  classCounts: Array<[string, number]>;
  controlsLocked: boolean;
  confirmation?: Confirmation;
};

export function ScanDialogSetup({
  selection,
  scanner,
  discovery,
  action,
  classCounts,
  controlsLocked,
  confirmation,
}: Props) {
  return (
    <>
      <div className="flex shrink-0 flex-wrap items-end gap-3 rounded-md border border-border bg-muted/30 p-3">
        {selection.allowAllTargets ? (
          <label className="flex flex-col gap-1 text-xs">
            Targets
            <SegmentedControl<Scope>
              size="sm"
              value={selection.scope}
              onChange={selection.onScopeChange}
              options={[
                {
                  id: "selected",
                  label: `Selected (${selection.selectedCount})`,
                  disabled: selection.selectedCount === 0 || controlsLocked,
                },
                {
                  id: "all",
                  label: `All targets (${selection.rowCount})`,
                  disabled: controlsLocked,
                },
              ]}
            />
          </label>
        ) : (
          <span className="flex flex-col gap-1 text-xs">
            Target
            <code className="h-control-h rounded-md border border-input bg-background px-3 py-2 text-sm">
              {selection.targetId}
            </code>
          </span>
        )}

        {scanner ? (
          <>
            <label className="flex flex-col gap-1 text-xs">
              Engine
              {scanner.engines.length > 1 ? (
                <Select
                  className="w-40"
                  value={scanner.engineName}
                  disabled={controlsLocked}
                  options={scanner.engines.map((engine) => ({
                    value: engine.name,
                    label: engine.title,
                  }))}
                  onChange={(event) => scanner.onChooseEngine(event.target.value)}
                />
              ) : (
                <span className="h-control-h rounded-md border border-input bg-background px-3 py-2 text-sm">
                  {scanner.selectedEngine?.title ?? scanner.engineName}
                </span>
              )}
            </label>
            <label className="flex flex-col gap-1 text-xs">
              Profile
              {scanner.profiles.length > 1 ? (
                <Select
                  className="w-52"
                  value={scanner.profileName}
                  disabled={controlsLocked}
                  options={scanner.profiles.map((profile) => ({
                    value: profile.name,
                    label: profile.name,
                  }))}
                  onChange={(event) => scanner.onChooseProfile(event.target.value)}
                />
              ) : (
                <span className="h-control-h rounded-md border border-input bg-background px-3 py-2 text-sm">
                  {scanner.profileName}
                </span>
              )}
              {scanner.engineName === "nuclei" ? (
                <TemplateSummary
                  preview={scanner.preview}
                  error={scanner.previewError}
                  loading={scanner.previewLoading}
                />
              ) : null}
            </label>
            {scanner.editableProfile && scanner.profileEdits ? (
              <label className="flex flex-col gap-1 text-xs">
                Keep as profile
                <span className="flex items-center gap-2">
                  <input
                    value={scanner.newProfileName}
                    onChange={(event) => scanner.onNewProfileName(event.target.value)}
                    placeholder="app-deep"
                    aria-label="New scan profile name"
                    disabled={controlsLocked || scanner.keeping}
                    className="h-control-h w-40 rounded-md border border-input bg-background px-2 text-sm"
                  />
                  <Button
                    size="sm"
                    variant="outline"
                    loading={scanner.keeping}
                    disabled={controlsLocked || scanner.keeping || !scanner.nameable}
                    onClick={scanner.onKeepAs}
                  >
                    Save as
                  </Button>
                </span>
                <span className="text-muted-foreground">
                  {scanner.nameTaken
                    ? `${scanner.engineName} already has a profile called "${scanner.newProfileName}"`
                    : scanner.newProfileName && !PROFILE_NAME.test(scanner.newProfileName)
                      ? "Lowercase letters, digits and dashes only"
                      : "This run uses these options either way"}
                </span>
              </label>
            ) : null}
          </>
        ) : null}

        <span className="flex flex-col gap-1 text-xs">
          Discovery profiles
          <Button
            size="sm"
            variant="outline"
            aria-expanded={discovery.editing}
            disabled={controlsLocked || !discovery.profiles.loaded}
            onClick={() => discovery.onEditingChange(!discovery.editing)}
          >
            {discovery.editing ? "Done editing" : "Edit profiles"}
          </Button>
        </span>
        <span className="flex flex-wrap items-center gap-1 pb-1.5 text-xs text-muted-foreground">
          {classCounts.map(([targetClass, count]) => (
            <span key={targetClass} className="rounded bg-muted px-1.5 py-0.5">
              {count} {targetClass}
            </span>
          ))}
          {describeSelection(discovery.profiles).map(({ engine, name }) => (
            <span key={engine} className="rounded bg-muted px-1.5 py-0.5">
              {engine} · {name}
            </span>
          ))}
          {discovery.profiles.edited ? (
            <span className="text-amber-600 dark:text-amber-400">
              discovery reconfigured for this run only
            </span>
          ) : null}
        </span>
        <span className="flex-1" />

        {action.discoveryOnly && action.discovering ? (
          <Button disabled loading>
            Rescanning…
          </Button>
        ) : (
          <>
            {!action.discoveryOnly && action.scanActive ? (
              <Button variant="destructive" onClick={action.onStop}>
                Cancel active scan
              </Button>
            ) : null}
            <Button
              onClick={action.onStart}
              loading={action.starting}
              disabled={
                action.starting ||
                action.targetCount === 0 ||
                !action.catalogLoaded ||
                (action.needsConfirm && !action.confirmed)
              }
            >
              {action.discoveryOnly
                ? "Rescan"
                : action.scanActive
                  ? "Queue scan"
                  : "Scan"}{" "}
              {action.targetCount} {action.targetNoun}
              {action.targetCount === 1 ? "" : "s"}
            </Button>
          </>
        )}
      </div>

      {confirmation && !controlsLocked ? (
        <label className="flex shrink-0 items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={confirmation.confirmed}
            onChange={(event) => confirmation.onConfirmedChange(event.target.checked)}
          />
          <span>
            This scan may send <strong>intrusive payloads</strong> at{" "}
            <strong>{confirmation.targetIds.length}</strong> prod/public or unsaved target
            {confirmation.targetIds.length === 1 ? "" : "s"} ({confirmation.targetIds.join(", ")}).
            I authorise this scan.
          </span>
        </label>
      ) : null}
    </>
  );
}
