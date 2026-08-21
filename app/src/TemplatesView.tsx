import { useEffect, useMemo, useState } from "react";
import { Select } from "@flanksource/clicky-ui/components";
import { DataTable } from "@flanksource/clicky-ui/data";
import { fetchEngines, fetchProfiles, fetchTemplates } from "./api";
import { selectionQuery, useEntityFilters } from "./filters";
import { TemplateDetail, visibleTemplateColumns } from "./templateColumns";
import { profileId } from "./types";
import type { Engine, Profile, Template } from "./types";

// The catalogue is over thirteen thousand templates. The table pages through
// whatever the server returns, and this is what it is asked for: enough to work
// with, bounded so a filter that matches everything does not become a download.
const PAGE = 500;

type Props = {
  /** Preselects the profile whose templates to show, from ?profile= */
  profile?: string;
  engine?: string;
  onSelectProfile?: (profile: string | undefined) => void;
  onSelectEngine?: (engine: string | undefined) => void;
};

function pluralize(label: string): string {
  const words = label.split(" ");
  const word = words.pop() ?? label;
  const suffix = /[^aeiou]y$/i.test(word)
    ? `${word.slice(0, -1)}ies`
    : /(s|x|z|ch|sh)$/i.test(word)
      ? `${word}es`
      : `${word}s`;
  return [...words, suffix].join(" ");
}

function profileEngine(reference: string | undefined): string | undefined {
  const parts = reference?.split(":") ?? [];
  return parts.length === 3 ? parts[1] : undefined;
}

function providerName(profile: Profile): string | undefined {
  return typeof profile.config.provider === "string" ? profile.config.provider : undefined;
}

/**
 * TemplatesView browses what the scan engines could run.
 *
 * Separate from a profile on purpose: "which templates cover Kubernetes" is a
 * question worth answering before deciding what a profile should contain, and
 * previously the only way to find out was to run a scan and read the findings.
 */
export function TemplatesView({ engine, profile, onSelectEngine, onSelectProfile }: Props) {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [engines, setEngines] = useState<Engine[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  const {
    filters,
    selection,
    error: filterError,
  } = useEntityFilters("template", { exclude: ["profile", "engine"] });

  const activeEngine = profileEngine(profile) ?? engine;
  const catalogue = engines.find((item) => item.name === activeEngine);
  const itemLabel = catalogue?.templates?.itemLabel ?? "catalog item";
  const profileLabel = catalogue?.templates?.profileLabel ?? "profile";

  useEffect(() => {
    let cancelled = false;
    Promise.all([fetchProfiles({ kind: "scan" }), fetchEngines("scan")])
      .then(([loadedProfiles, loadedEngines]) => {
        if (cancelled) return;
        setProfiles(loadedProfiles);
        setEngines(loadedEngines.filter((item) => item.templates));
      })
      .catch((reason) => !cancelled && setError((reason as Error).message));
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setBusy(true);
    fetchTemplates({
      ...selectionQuery(selection),
      engine: activeEngine,
      profile,
      limit: PAGE,
    })
      .then((result) => {
        if (cancelled) return;
        setTemplates(result);
        setError(null);
      })
      .catch((reason) => !cancelled && setError((reason as Error).message))
      .finally(() => !cancelled && setBusy(false));
    return () => {
      cancelled = true;
    };
  }, [selection, activeEngine, profile]);

  const catalogueOptions = useMemo(
    () => [
      { value: "", label: "All catalogues" },
      ...engines.map((item) => ({
        value: item.name,
        label: `${item.title} ${pluralize(item.templates?.itemLabel ?? "catalog item")}`,
      })),
    ],
    [engines],
  );

  const profileOptions = useMemo(
    () => [
      { value: "", label: `All ${pluralize(profileLabel)}` },
      ...profiles
        .filter((item) => !activeEngine || item.engine === activeEngine)
        .map((item) => ({
          value: profileId(item),
          label: activeEngine
            ? `${item.name}${providerName(item) ? ` (${providerName(item)})` : ""}`
            : `${item.name} (${item.engine})`,
        })),
    ],
    [activeEngine, profileLabel, profiles],
  );
  const columns = useMemo(
    () => visibleTemplateColumns(templates, { itemLabel, showEngine: !activeEngine }),
    [activeEngine, itemLabel, templates],
  );
  const shownLabel = templates.length === 1 ? itemLabel : pluralize(itemLabel);

  return (
    <div className="flex h-full flex-col">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <div>
          <h1 className="text-lg font-semibold">Templates</h1>
          <p className="text-xs text-muted-foreground">
            Templates, checks and policies a scan engine can run
          </p>
        </div>
        <span className="flex-1" />
        <label htmlFor="templates-engine" className="text-xs text-muted-foreground">
          Catalogue
        </label>
        <Select
          id="templates-engine"
          className="w-48"
          value={activeEngine ?? ""}
          options={catalogueOptions}
          onChange={(event) => onSelectEngine?.(event.target.value || undefined)}
        />
        <label htmlFor="templates-profile" className="text-xs text-muted-foreground">
          {profileLabel.charAt(0).toUpperCase() + profileLabel.slice(1)}
        </label>
        <Select
          id="templates-profile"
          className="w-56"
          value={profile ?? ""}
          options={profileOptions}
          onChange={(event) => onSelectProfile?.(event.target.value || undefined)}
        />
      </header>

      <main className="min-h-0 flex-1 overflow-y-auto p-4">
        {(error ?? filterError) && (
          <div role="alert" className="mb-3 text-sm text-destructive">
            {error ?? filterError}
          </div>
        )}

        <div className="mb-2 flex items-center gap-2">
          <span className="text-sm text-muted-foreground">
            {busy
              ? `Loading ${pluralize(itemLabel)}…`
              : `${templates.length.toLocaleString()} ${shownLabel} shown`}
          </span>
          {/* The server caps a listing, so a full page means there is more
              behind it. Saying so beats a count that looks complete. */}
          {!busy && templates.length >= PAGE && (
            <span className="text-xs text-muted-foreground">
              — capped at {PAGE.toLocaleString()}; narrow the filters to see the rest
            </span>
          )}
        </div>

        <DataTable<Template>
          data={templates}
          columns={columns}
          getRowId={(row) => `${row.engine}:${row.path}`}
          externalFilters={filters}
          showGlobalFilter
          globalFilterPlaceholder={`Search ${pluralize(itemLabel)} by id, name or path…`}
          defaultSort={{ key: "severity" }}
          emptyMessage={
            profile
              ? `This ${profileLabel} selects no ${pluralize(itemLabel)}.`
              : `No ${pluralize(itemLabel)} match these filters.`
          }
          detailStyle="row"
          renderExpandedRow={(row) => <TemplateDetail template={row} />}
          isRowClickable={() => true}
        />
      </main>
    </div>
  );
}

// Re-exported so a caller can address a profile the same way the API does.
export { profileId };
