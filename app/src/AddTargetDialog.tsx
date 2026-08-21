import { useEffect, useMemo, useState } from "react";
import { Button, Modal, SegmentedControl, Select } from "@flanksource/clicky-ui/components";
import { addTarget, fetchEngines, fetchProfiles } from "./api";
import { ProviderContextConfiguration } from "./ProviderContextConfiguration";
import { resolveProviderContextEngine } from "./TargetView";
import { AddTargetFields, type Draft } from "./AddTargetFields";
import type {
  Engine,
  Profile,
  TargetDocument,
  TargetKind,
} from "./types";

type Props = {
  open: boolean;
  onClose: () => void;
  onCreated: (target: TargetDocument) => void;
  tagVocabulary: string[];
};

// The steps a target is defined in. Identity and configuration are separate
// because a provider context cannot offer either until a provider is chosen:
// the scope arguments are that provider's own schema, and the profiles are the
// subset written against it.
const STEPS = ["kind", "identity", "configure"] as const;
type Step = (typeof STEPS)[number];

const STEP_TITLES: Record<Step, string> = {
  kind: "What are you adding?",
  identity: "Identity",
  configure: "Configuration",
};

const KIND_CHOICES: { kind: TargetKind; label: string; blurb: string }[] = [
  {
    kind: "host",
    label: "Host",
    blurb:
      "Something on the network with an address and ports. Discovery, liveness probes and endpoint scans all reach it.",
  },
  {
    kind: "provider-context",
    label: "Provider context",
    blurb:
      "A provider-native scan scope — a cloud account, an organization, a repository. Audited through the provider's API, never contacted over the network.",
  },
];

const emptyDraft: Draft = {
  kind: "host",
  id: "",
  host: "",
  provider: "",
  credentialMode: "ambient",
  arguments: {},
  class: "unclassified",
  profiles: [],
  tags: [],
  app: "",
  cluster: "",
  notes: "",
};

export function AddTargetDialog({ open, onClose, onCreated, tagVocabulary }: Props) {
  const [step, setStep] = useState<Step>("kind");
  const [draft, setDraft] = useState<Draft>(emptyDraft);
  const [engines, setEngines] = useState<Engine[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // Reset on open rather than on close, so the fields do not visibly empty
  // themselves while the dialog animates away.
  useEffect(() => {
    if (!open) return;
    setStep("kind");
    setDraft(emptyDraft);
    setError(null);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    let live = true;
    setCatalogError(null);
    void Promise.all([fetchEngines("scan"), fetchProfiles({ kind: "scan" })])
      .then(([loadedEngines, loadedProfiles]) => {
        if (!live) return;
        setEngines(loadedEngines);
        setProfiles(loadedProfiles);
      })
      .catch((cause: Error) => live && setCatalogError(cause.message));
    return () => {
      live = false;
    };
  }, [open]);

  // Every provider any scan engine declares a context schema for. This is what
  // makes the picker honest: it offers exactly the providers something can
  // actually scan, rather than a list maintained by hand here.
  const providers = useMemo(() => providerOptions(engines), [engines]);

  const providerEngine = useMemo(() => {
    if (draft.kind !== "provider-context" || !draft.provider) return null;
    try {
      return { engine: resolveProviderContextEngine(engines, draft.provider) };
    } catch (cause) {
      return { error: (cause as Error).message };
    }
  }, [engines, draft.kind, draft.provider]);

  // A profile written for one provider means nothing to another — prowler ships
  // well over a hundred across every provider it supports — so offering the
  // whole catalogue would bury the handful that apply.
  const offered = useMemo(
    () => offeredProfiles(profiles, engines, draft.kind, draft.provider),
    [profiles, engines, draft.kind, draft.provider],
  );

  const identityComplete =
    draft.kind === "host"
      ? draft.host.trim() !== ""
      : draft.id.trim() !== "" && draft.provider !== "";

  const create = async () => {
    setSaving(true);
    setError(null);
    try {
      const created = await addTarget(
        draft.kind === "host"
          ? {
              kind: "host",
              id: draft.host.trim(),
              host: draft.host.trim(),
              ...curation(draft),
            }
          : {
              kind: "provider-context",
              id: draft.id.trim(),
              provider: draft.provider,
              credentialMode: draft.credentialMode,
              arguments: draft.arguments,
              ...(draft.credentials ? { credentials: draft.credentials } : {}),
              ...curation(draft),
            },
      );
      onCreated(created);
      onClose();
    } catch (cause) {
      setError((cause as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const index = STEPS.indexOf(step);

  return (
    <Modal open={open} onClose={onClose} title="Add target" size="lg">
      <div className="flex min-h-0 flex-1 flex-col gap-4">
        <ol className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
          {STEPS.map((name, position) => (
            <li key={name} className="flex items-center gap-2">
              <span
                className={
                  position === index
                    ? "rounded-full bg-primary px-2 py-0.5 text-primary-foreground"
                    : "rounded-full bg-muted px-2 py-0.5"
                }
              >
                {position + 1}. {STEP_TITLES[name]}
              </span>
              {position < STEPS.length - 1 ? <span aria-hidden>→</span> : null}
            </li>
          ))}
        </ol>

        {catalogError ? (
          <p
            className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
            role="alert"
          >
            {catalogError}
          </p>
        ) : null}

        <div className="min-h-0 flex-1 overflow-y-auto">
          {step === "kind" ? (
            <fieldset className="flex flex-col gap-2">
              <legend className="sr-only">Target kind</legend>
              {KIND_CHOICES.map((choice) => (
                <label
                  key={choice.kind}
                  className={`flex cursor-pointer gap-3 rounded-md border p-3 text-sm ${
                    draft.kind === choice.kind
                      ? "border-primary bg-primary/5"
                      : "border-border"
                  }`}
                >
                  <input
                    type="radio"
                    name="target-kind"
                    className="mt-1"
                    checked={draft.kind === choice.kind}
                    onChange={() =>
                      setDraft((current) => ({
                        ...current,
                        kind: choice.kind,
                        // Profiles are per-kind and often per-provider, so a
                        // selection made for one kind cannot survive the switch.
                        profiles: [],
                      }))
                    }
                  />
                  <span className="flex flex-col gap-1">
                    <span className="font-medium">{choice.label}</span>
                    <span className="text-muted-foreground">{choice.blurb}</span>
                  </span>
                </label>
              ))}
            </fieldset>
          ) : null}

          {step === "identity" ? (
            <div className="flex flex-col gap-3">
              {draft.kind === "host" ? (
                <Labelled
                  label="Host"
                  hint="The address a scan connects to. It is also the target's id."
                >
                  <input
                    className="h-control-h w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                    value={draft.host}
                    autoFocus
                    placeholder="api.example.com"
                    onChange={(event) =>
                      setDraft((current) => ({ ...current, host: event.target.value }))
                    }
                  />
                </Labelled>
              ) : (
                <>
                  <Labelled
                    label="Id"
                    hint="A stable name for this scope. Independent of whichever accounts or resources its arguments currently select."
                  >
                    <input
                      className="h-control-h w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                      value={draft.id}
                      autoFocus
                      placeholder="gcp-production"
                      onChange={(event) =>
                        setDraft((current) => ({ ...current, id: event.target.value }))
                      }
                    />
                  </Labelled>
                  <Labelled label="Provider">
                    <Select
                      className="w-full"
                      value={draft.provider}
                      options={[
                        { value: "", label: "Choose a provider…" },
                        ...providers,
                      ]}
                      onChange={(event) =>
                        setDraft((current) => ({
                          ...current,
                          provider: event.target.value,
                          // The arguments belong to the provider's own schema
                          // and its profiles are written against it, so neither
                          // survives changing which provider this is.
                          arguments: {},
                          credentials: undefined,
                          profiles: [],
                        }))
                      }
                    />
                  </Labelled>
                  <Labelled
                    label="Credentials"
                    hint="Ambient uses whatever the scanning process already has. Configured selects an explicit runtime credential below."
                  >
                    <SegmentedControl
                      size="sm"
                      value={draft.credentialMode}
                      onChange={(mode) =>
                        setDraft((current) => ({
                          ...current,
                          credentialMode: mode,
                          ...(mode === "ambient" ? { credentials: undefined } : {}),
                        }))
                      }
                      options={[
                        { id: "ambient", label: "Ambient" },
                        { id: "configured", label: "Configured" },
                      ]}
                    />
                  </Labelled>
                </>
              )}
            </div>
          ) : null}

          {step === "configure" ? (
            <div className="flex flex-col gap-4">
              {draft.kind === "provider-context" && providerEngine?.error ? (
                <p
                  className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
                  role="alert"
                >
                  {providerEngine.error}
                </p>
              ) : null}
              {draft.kind === "provider-context" && providerEngine?.engine ? (
                <ProviderContextConfiguration
                  engine={providerEngine.engine}
                  identity={`new:${draft.provider}:context`}
                  provider={draft.provider}
                  credentialMode={draft.credentialMode}
                  arguments={draft.arguments}
                  onArgumentsChange={(arguments_) =>
                    setDraft((current) => ({ ...current, arguments: arguments_ }))
                  }
                  credentials={draft.credentials}
                  onCredentialsChange={(credentials) =>
                    setDraft((current) => ({
                      ...current,
                      credentials: credentials ?? undefined,
                    }))
                  }
                  note="Scope arguments are validated against the selected provider when the target is created."
                />
              ) : null}
              <AddTargetFields
                draft={draft}
                onChange={setDraft}
                profiles={offered}
                tagVocabulary={tagVocabulary}
              />
            </div>
          ) : null}
        </div>

        {error ? (
          <p
            className="shrink-0 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
            role="alert"
          >
            {error}
          </p>
        ) : null}

        <div className="flex shrink-0 items-center gap-2 border-t border-border pt-3">
          <Button variant="ghost" size="sm" onClick={onClose} disabled={saving}>
            Cancel
          </Button>
          <span className="flex-1" />
          {index > 0 ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setStep(STEPS[index - 1])}
              disabled={saving}
            >
              Back
            </Button>
          ) : null}
          {step === "configure" ? (
            <Button
              size="sm"
              onClick={() => void create()}
              loading={saving}
              disabled={saving || draft.profiles.length === 0}
            >
              Add target
            </Button>
          ) : (
            <Button
              size="sm"
              onClick={() => setStep(STEPS[index + 1])}
              disabled={step === "identity" && !identityComplete}
            >
              Next
            </Button>
          )}
        </div>
      </div>
    </Modal>
  );
}

function Labelled({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs">
      <span className="font-medium">{label}</span>
      {children}
      {hint ? <span className="text-muted-foreground">{hint}</span> : null}
    </label>
  );
}

// providerOptions lists every provider a scan engine declares a context schema
// for, labelled with the variant's own title.
export function providerOptions(engines: Engine[]): { value: string; label: string }[] {
  const seen = new Map<string, string>();
  for (const engine of engines) {
    if (engine.options.discriminator !== "provider") continue;
    for (const variant of engine.options.variants) {
      if (variant.contextSchema && !seen.has(variant.id)) {
        seen.set(variant.id, variant.title || variant.id);
      }
    }
  }
  return [...seen.entries()]
    .map(([value, label]) => ({ value, label }))
    .sort((left, right) => left.label.localeCompare(right.label));
}

// offeredProfiles narrows the scan catalogue to the profiles that can actually
// run against what is being added.
//
// A host is offered only the engines whose subject is an address. That is the
// engine's own declaration, not a guess from whether it has providers: inspec
// audits a cloud account and has no providers, so inferring it from that would
// offer a compliance profile against a hostname it can never reach.
//
// A provider context is offered only the profiles written for its own provider,
// which each profile records in its config — so this reads the catalogue rather
// than parsing profile names.
export function offeredProfiles(
  profiles: Profile[],
  engines: Engine[],
  kind: TargetKind,
  provider: string,
): Profile[] {
  const byName = new Map(engines.map((engine) => [engine.name, engine]));
  if (kind === "host") {
    return profiles.filter((profile) => !byName.get(profile.engine)?.subject);
  }
  if (!provider) return [];
  return profiles.filter(
    (profile) =>
      byName.get(profile.engine)?.options.discriminator === "provider" &&
      profile.config?.provider === provider,
  );
}

// curation is the curated half of a create body. Empty optional strings are
// dropped rather than sent: the schema gives them minLength 1, so "" is not the
// same as absent and would be refused.
function curation(draft: Draft) {
  return {
    class: draft.class,
    profiles: draft.profiles,
    tags: draft.tags,
    source: "manual",
    ...(draft.app.trim() ? { app: draft.app.trim() } : {}),
    ...(draft.cluster.trim() ? { cluster: draft.cluster.trim() } : {}),
    ...(draft.notes.trim() ? { notes: draft.notes.trim() } : {}),
  };
}
