import { useEffect, useMemo, useState } from "react";
import { DataTable, Select } from "@flanksource/clicky-ui";
import { fetchProfiles, fetchTemplates } from "./api";
import { selectionQuery, useEntityFilters } from "./filters";
import { TemplateDetail, templateColumns } from "./templateColumns";
import { profileId } from "./types";
import type { Profile, Template } from "./types";

// The catalogue is over thirteen thousand templates. The table pages through
// whatever the server returns, and this is what it is asked for: enough to work
// with, bounded so a filter that matches everything does not become a download.
const PAGE = 500;

type Props = {
  /** Preselects the profile whose templates to show, from ?profile= */
  profile?: string;
  onSelectProfile?: (profile: string | undefined) => void;
};

/**
 * TemplatesView browses what the scan engines could run.
 *
 * Separate from a profile on purpose: "which templates cover Kubernetes" is a
 * question worth answering before deciding what a profile should contain, and
 * previously the only way to find out was to run a scan and read the findings.
 */
export function TemplatesView({ profile, onSelectProfile }: Props) {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);

  const {
    filters,
    selection,
    error: filterError,
  } = useEntityFilters("template", { exclude: ["profile", "engine"] });

  useEffect(() => {
    let cancelled = false;
    fetchProfiles({ kind: "scan" })
      .then((result) => !cancelled && setProfiles(result))
      .catch((reason) => !cancelled && setError((reason as Error).message));
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setBusy(true);
    fetchTemplates({ ...selectionQuery(selection), profile, limit: PAGE })
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
  }, [selection, profile]);

  const profileOptions = useMemo(
    () => [
      { value: "", label: "All templates" },
      ...profiles.map((item) => ({ value: item.name, label: `${item.name} (${item.engine})` })),
    ],
    [profiles],
  );

  return (
    <div className="flex h-full flex-col">
      <header className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <div>
          <h1 className="text-lg font-semibold">Templates</h1>
          <p className="text-xs text-muted-foreground">
            What a scan can check, and which profile would run it
          </p>
        </div>
        <span className="flex-1" />
        <label htmlFor="templates-profile" className="text-xs text-muted-foreground">
          Profile
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
            {busy ? "Loading templates…" : `${templates.length.toLocaleString()} shown`}
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
          columns={templateColumns}
          getRowId={(row) => `${row.engine}:${row.path}`}
          externalFilters={filters}
          showGlobalFilter
          globalFilterPlaceholder="Search templates by id, name or path…"
          defaultSort={{ key: "severity" }}
          emptyMessage={
            profile
              ? "This profile selects no templates."
              : "No templates match these filters."
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
