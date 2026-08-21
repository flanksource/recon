import { Select } from "@flanksource/clicky-ui/components";
import {
  CLASS_ORDER,
  profileId,
  type CredentialMode,
  type Profile,
  type TargetClass,
  type TargetCredentials,
  type TargetKind,
} from "./types";

// Draft is the dialog's working state: every field a create can set, flat, with
// the provider-context ones present but unused for a host. Kept as one shape so
// switching kind never loses what was already typed.
export type Draft = {
  kind: TargetKind;
  id: string;
  host: string;
  provider: string;
  credentialMode: CredentialMode;
  arguments: Record<string, unknown>;
  credentials?: TargetCredentials;
  class: TargetClass;
  profiles: string[];
  tags: string[];
  app: string;
  cluster: string;
  notes: string;
};

type Props = {
  draft: Draft;
  onChange: (update: (current: Draft) => Draft) => void;
  profiles: Profile[];
  tagVocabulary: string[];
};

// The curated fields, which mean the same thing whatever the target is: how
// exposed it is, what scans it, and how it is grouped.
export function AddTargetFields({ draft, onChange, profiles, tagVocabulary }: Props) {
  const chosen = new Set(draft.profiles);

  const toggleProfile = (id: string) =>
    onChange((current) => ({
      ...current,
      profiles: current.profiles.includes(id)
        ? current.profiles.filter((name) => name !== id)
        : [...current.profiles, id],
    }));

  return (
    <div className="flex flex-col gap-3">
      <label className="flex flex-col gap-1 text-xs">
        <span className="font-medium">Class</span>
        <Select
          className="w-full"
          value={draft.class}
          options={CLASS_ORDER.map((name) => ({ value: name, label: name }))}
          onChange={(event) =>
            onChange((current) => ({
              ...current,
              class: event.target.value as TargetClass,
            }))
          }
        />
        <span className="text-muted-foreground">
          How exposed this is. It decides whether an intrusive scan needs
          confirming, so it is worth getting right.
        </span>
      </label>

      <fieldset className="flex flex-col gap-1 text-xs">
        <legend className="font-medium">Scan profiles</legend>
        {profiles.length === 0 ? (
          <p className="text-muted-foreground">
            {draft.kind === "provider-context" && !draft.provider
              ? "Choose a provider to see the profiles written for it."
              : "No scan profile applies to this target yet."}
          </p>
        ) : (
          <div className="max-h-48 overflow-y-auto rounded-md border border-border">
            {profiles.map((profile) => {
              const id = profileId(profile);
              return (
                <label
                  key={id}
                  className="flex cursor-pointer items-center gap-2 border-b border-border px-2 py-1 last:border-b-0"
                >
                  <input
                    type="checkbox"
                    checked={chosen.has(id)}
                    onChange={() => toggleProfile(id)}
                  />
                  <span className="font-mono">{profile.name}</span>
                  {profile.intrusive ? (
                    <span className="rounded bg-destructive/10 px-1 text-destructive">
                      intrusive
                    </span>
                  ) : null}
                </label>
              );
            })}
          </div>
        )}
        <span className="text-muted-foreground">
          At least one is required — a target no profile names is one nothing
          ever scans.
        </span>
      </fieldset>

      <label className="flex flex-col gap-1 text-xs">
        <span className="font-medium">Tags</span>
        <input
          className="h-control-h w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
          value={draft.tags.join(", ")}
          placeholder="team=platform, cloud"
          list="add-target-tags"
          onChange={(event) =>
            onChange((current) => ({
              ...current,
              tags: event.target.value
                .split(",")
                .map((tag) => tag.trim())
                .filter(Boolean),
            }))
          }
        />
        <datalist id="add-target-tags">
          {tagVocabulary.map((tag) => (
            <option key={tag} value={tag} />
          ))}
        </datalist>
        <span className="text-muted-foreground">
          Comma separated. `key=value` tags are selectable with --selector.
        </span>
      </label>

      <div className="grid grid-cols-2 gap-3">
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-medium">App</span>
          <input
            className="h-control-h w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={draft.app}
            onChange={(event) =>
              onChange((current) => ({ ...current, app: event.target.value }))
            }
          />
        </label>
        <label className="flex flex-col gap-1 text-xs">
          <span className="font-medium">Cluster</span>
          <input
            className="h-control-h w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            value={draft.cluster}
            onChange={(event) =>
              onChange((current) => ({ ...current, cluster: event.target.value }))
            }
          />
        </label>
      </div>

      <label className="flex flex-col gap-1 text-xs">
        <span className="font-medium">Notes</span>
        <textarea
          className="min-h-16 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
          value={draft.notes}
          onChange={(event) =>
            onChange((current) => ({ ...current, notes: event.target.value }))
          }
        />
      </label>
    </div>
  );
}
