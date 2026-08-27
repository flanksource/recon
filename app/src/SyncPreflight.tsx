import type { InsightAmbiguity, InsightChoice, InsightSync, InsightUnresolved } from "./types";

/**
 * What a sync would do, before it does it.
 *
 * The counters are the summary; the two lists below them are the reasons a
 * number is lower than expected. Ambiguity comes first because it is the only
 * part a person can act on from here: an identity several config items carry is
 * not a miss, it is a question, and answering it is what attaches those
 * findings.
 */
export function SyncPreflight({
  result,
  pushed,
  choices,
  onChoose,
}: {
  result: InsightSync;
  pushed: boolean;
  choices: Record<string, string>;
  onChoose: (identity: string, configId: string) => void;
}) {
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-3">
        <Count label="Resources" value={result.matchedResources} />
        <Count label="States" value={result.matchedStates} />
        <Count label="Eligible" value={result.eligible} />
        <Count label="Skipped" value={result.skipped} />
      </div>
      <div className="flex flex-wrap gap-3">
        <Count label="Open" value={result.open} />
        <Count label="Resolved" value={result.resolved} />
        <Count label="Silenced" value={result.silenced} />
        <Count label="Direct" value={result.direct} />
        <Count label="Rolled up" value={result.rolledUp} />
        {result.pinned > 0 && <Count label="Chosen" value={result.pinned} />}
        {pushed && <Count label="Pushed" value={result.pushed} />}
      </div>

      {result.server && (
        <p className="text-xs text-muted-foreground">
          {pushed ? "Synced to" : "Would sync to"} {result.server} as agent <code>{result.agent}</code>
        </p>
      )}

      {result.ambiguous.length > 0 && (
        <AmbiguityChooser
          ambiguous={result.ambiguous}
          choices={choices}
          onChoose={onChoose}
          decided={pushed}
        />
      )}
      {result.configs.length > 0 && <ConfigList configs={result.configs} />}
      {result.unresolved.length > 0 && <UnresolvedList unresolved={result.unresolved} />}
    </div>
  );
}

function Count({ label, value }: { label: string; value: number }) {
  return (
    <div className="min-w-24 rounded-md border border-border bg-muted/30 p-3">
      <div className="text-lg font-semibold">{value}</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}

function AmbiguityChooser({
  ambiguous,
  choices,
  onChoose,
  decided,
}: {
  ambiguous: InsightAmbiguity[];
  choices: Record<string, string>;
  onChoose: (identity: string, configId: string) => void;
  /** The sync has run: this is now the record of what was chosen, not the question. */
  decided: boolean;
}) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h3 className="text-xs font-medium text-muted-foreground">
          Matched more than one config item — choose where these belong
        </h3>
        <p className="text-xs text-muted-foreground">
          The choice is remembered against each resource once the sync runs.
        </p>
      </div>
      {ambiguous.map((item) => (
        <div key={item.identity} className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
          <div className="text-sm">
            <span className="font-medium">{item.identity}</span>
            <span className="text-muted-foreground">
              {" · "}
              {item.states} {item.states === 1 ? "state" : "states"}
              {item.scope && " · account or cluster"}
            </span>
            {item.resources && item.resources.length > 0 && (
              <div className="truncate text-xs text-muted-foreground">{item.resources.join(", ")}</div>
            )}
          </div>
          <ul role="radiogroup" aria-label={`Config item for ${item.identity}`} className="mt-2 flex flex-col gap-1">
            {item.options.map((option) => (
              <li key={option.id}>
                <label className="flex cursor-pointer items-baseline gap-2 text-sm">
                  <input
                    type="radio"
                    name={`ambiguity-${item.identity}`}
                    value={option.id}
                    checked={(choices[item.identity] ?? item.chosen) === option.id}
                    disabled={decided}
                    onChange={() => onChoose(item.identity, option.id)}
                  />
                  <span className="truncate">{describeChoice(option)}</span>
                </label>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </section>
  );
}

function describeChoice(option: InsightChoice): string {
  const notes = [
    option.type,
    option.ancestor ? "contains the matches" : null,
    option.root ? "root" : null,
    option.deleted ? "deleted" : null,
  ].filter(Boolean);
  return [option.name || option.id, ...notes].join(" · ");
}

function ConfigList({ configs }: { configs: InsightSync["configs"] }) {
  return (
    <div className="flex flex-col gap-1">
      <h3 className="text-xs font-medium text-muted-foreground">Config items</h3>
      <ul className="max-h-48 overflow-y-auto text-sm">
        {configs.map((config) => (
          <li key={config.id} className="flex items-baseline justify-between gap-2 py-0.5">
            <span className="truncate">
              {config.name || config.id}
              {config.type && <span className="text-muted-foreground"> · {config.type}</span>}
              {config.rolledUp && <span className="text-amber-600 dark:text-amber-400"> · rolled up</span>}
              {config.pinned && <span className="text-muted-foreground"> · chosen</span>}
            </span>
            <span className="shrink-0 tabular-nums text-muted-foreground">{config.insights}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Grouped by reason rather than one row per finding: a scan of an estate the
 * catalog does not hold produces thousands of these, and they have a handful of
 * distinct causes between them. The count is what says how much is affected;
 * the identities are what says why.
 */
function UnresolvedList({ unresolved }: { unresolved: InsightUnresolved[] }) {
  const groups = new Map<string, { reason: string; count: number; hosts: string[] }>();
  for (const item of unresolved) {
    const group = groups.get(item.reason) ?? { reason: item.reason, count: 0, hosts: [] };
    group.count += 1;
    const host = item.host || item.finding;
    if (group.hosts.length < 5 && !group.hosts.includes(host)) group.hosts.push(host);
    groups.set(item.reason, group);
  }
  return (
    <div className="flex flex-col gap-1">
      <h3 className="text-xs font-medium text-muted-foreground">
        Not synced — nothing in the catalog carries these identities
      </h3>
      <ul className="max-h-48 overflow-y-auto text-sm">
        {[...groups.values()].map((group) => (
          <li key={group.reason} className="py-0.5">
            <span className="tabular-nums text-muted-foreground">{group.count}× </span>
            {group.reason}
            <div className="truncate text-xs text-muted-foreground">{group.hosts.join(", ")}</div>
          </li>
        ))}
      </ul>
    </div>
  );
}
