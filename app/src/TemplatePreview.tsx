import { useEffect, useRef, useState } from "react";
import { previewTemplates } from "./api";
import { SEVERITY_RANK, severityBadge } from "./scanColumns";
import type { Severity, TemplatePreview as Preview } from "./types";

// How long the form stays still before a preview is requested. Long enough that
// typing a tag does not issue a request per keystroke, short enough that the
// count feels attached to the edit that caused it.
const DEBOUNCE_MS = 350;

/**
 * usePreview answers "what would this configuration run" for a draft.
 *
 * The draft is what matters: a profile is edited before it is saved, and having
 * to save it to find out what a change did is exactly the loop this removes.
 */
export function usePreview(
  config: Record<string, unknown> | null,
  engine = "nuclei",
): { preview: Preview | null; error: string | null; loading: boolean } {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // The serialised config, so an identical object rebuilt on every render does
  // not look like a change.
  const key = config ? JSON.stringify(config) : null;

  // Bumped per request so a slow answer for an older draft cannot overwrite the
  // current one.
  const version = useRef(0);

  useEffect(() => {
    if (!key) {
      setPreview(null);
      setError(null);
      return;
    }

    const current = ++version.current;
    setLoading(true);
    const timer = setTimeout(() => {
      previewTemplates({ engine, config: JSON.parse(key) })
        .then((next) => {
          if (version.current !== current) return;
          setPreview(next);
          setError(null);
        })
        .catch((cause: Error) => {
          if (version.current !== current) return;
          // A configuration the engine rejects is worth showing: it is the same
          // message a scan would fail with, only sooner.
          setPreview(null);
          setError(cause.message);
        })
        .finally(() => {
          if (version.current === current) setLoading(false);
        });
    }, DEBOUNCE_MS);

    return () => clearTimeout(timer);
  }, [key, engine]);

  return { preview, error, loading };
}

const SEVERITY_ORDER = Object.keys(SEVERITY_RANK) as Severity[];

/** TemplateSummary is the one-line form, for the scan dialog. */
export function TemplateSummary({
  preview,
  error,
  loading,
}: {
  preview: Preview | null;
  error: string | null;
  loading: boolean;
}) {
  if (error) {
    return (
      <span role="alert" className="text-xs text-destructive">
        {error}
      </span>
    );
  }
  if (!preview) {
    return (
      <span className="text-xs text-muted-foreground">
        {loading ? "Counting templates…" : null}
      </span>
    );
  }

  const critical = preview.bySeverity.critical ?? 0;
  const high = preview.bySeverity.high ?? 0;
  return (
    <span
      aria-label="Templates this scan will run"
      className={`text-xs ${loading ? "opacity-50" : ""} text-muted-foreground`}
    >
      <strong className="text-foreground">{preview.total.toLocaleString()}</strong> templates
      {critical || high ? (
        <>
          {" · "}
          {critical ? `${critical} critical` : ""}
          {critical && high ? ", " : ""}
          {high ? `${high} high` : ""}
        </>
      ) : null}
      {preview.total === 0 ? " — this scan would check nothing" : null}
    </span>
  );
}

/** TemplatePreviewPanel is the full breakdown, for the profile editor. */
export function TemplatePreviewPanel({
  preview,
  error,
  loading,
  onBrowse,
}: {
  preview: Preview | null;
  error: string | null;
  loading: boolean;
  onBrowse?: () => void;
}) {
  if (error) {
    return (
      <div role="alert" className="rounded-md border border-destructive/40 bg-destructive/5 p-3 text-sm text-destructive">
        {error}
      </div>
    );
  }
  if (!preview) {
    return (
      <p className="text-sm text-muted-foreground">
        {loading ? "Counting templates…" : "No preview available."}
      </p>
    );
  }

  const severities = SEVERITY_ORDER.filter((s) => (preview.bySeverity[s] ?? 0) > 0);
  const protocols = Object.entries(preview.byType).sort((a, b) => b[1] - a[1]);

  return (
    <div className={`flex flex-col gap-4 ${loading ? "opacity-60" : ""}`}>
      <div className="flex items-baseline gap-3">
        <span aria-label="Templates selected" className="text-2xl font-semibold tabular-nums">
          {preview.total.toLocaleString()}
        </span>
        <span className="text-sm text-muted-foreground">
          templates
          {preview.maxRequests > 0 && (
            <>
              {" · up to "}
              <span className="tabular-nums">{preview.maxRequests.toLocaleString()}</span>
              {" requests per target"}
            </>
          )}
        </span>
      </div>

      {preview.total === 0 && (
        // Silence here would read as a working profile that happens to find
        // nothing, which is the failure this whole panel exists to prevent.
        <p role="alert" className="text-sm text-amber-600 dark:text-amber-400">
          This configuration selects no templates. A scan would report a clean
          result without checking anything.
        </p>
      )}

      {severities.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {severities.map((severity) => (
            <span key={severity} className="flex items-center gap-1.5">
              {severityBadge(severity)}
              <span className="text-sm tabular-nums text-muted-foreground">
                {preview.bySeverity[severity]?.toLocaleString()}
              </span>
            </span>
          ))}
        </div>
      )}

      {protocols.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase text-muted-foreground">Protocols</span>
          <div className="flex flex-wrap gap-2">
            {protocols.map(([type, count]) => (
              <span key={type} className="rounded bg-muted px-2 py-0.5 text-xs">
                {type} <span className="tabular-nums text-muted-foreground">{count.toLocaleString()}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {preview.byTag.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="text-xs font-semibold uppercase text-muted-foreground">Most common tags</span>
          <div className="flex flex-wrap gap-2">
            {preview.byTag.map((tag) => (
              <span key={tag.tag} className="rounded bg-muted px-2 py-0.5 text-xs">
                {tag.tag} <span className="tabular-nums text-muted-foreground">{tag.count.toLocaleString()}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {preview.caveats?.length ? (
        <ul className="list-inside list-disc text-xs text-muted-foreground">
          {preview.caveats.map((caveat) => (
            <li key={caveat}>{caveat}</li>
          ))}
        </ul>
      ) : null}

      {onBrowse && preview.total > 0 && (
        <button
          type="button"
          onClick={onBrowse}
          className="self-start text-sm text-primary hover:underline"
        >
          Browse these templates →
        </button>
      )}
    </div>
  );
}
