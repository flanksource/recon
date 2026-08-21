import { useMemo } from "react";
import type { ElementType } from "react";
import { Tree } from "@flanksource/clicky-ui/data";
import {
  UiFolder,
  UiNetwork,
  UiScan,
  UiShield,
  UiSliders,
  UiWrench,
} from "@flanksource/clicky-ui/icons";
import {
  Aws,
  Azure,
  Cloudflare,
  Docker,
  Gcp,
  Git,
  Github,
  Google,
  K8S,
  Microsoft,
  Mongodb,
  Okta,
  Oracle,
  Trivy,
} from "@flanksource/icons/mi";
import { profileId } from "./types";
import type { Profile } from "./types";

type ProfileTreeNode = {
  key: string;
  label: string;
  type: "kind" | "engine" | "provider" | "profile";
  kind: Profile["kind"];
  engineTitle?: string;
  provider?: string;
  icon?: ElementType;
  profile?: Profile;
  children: ProfileTreeNode[];
};

type Props = {
  profiles: Profile[];
  selectedId: string | null;
  engineTitle: (engine: string) => string;
  providerTitle: (engine: string, provider: string) => string;
  isDirty: (profile: Profile) => boolean;
  onSelect: (profile: Profile) => void;
};

const kindLabels: Record<Profile["kind"], string> = {
  discovery: "Discovery",
  scan: "Scan",
};

export function ProfileTree({
  profiles,
  selectedId,
  engineTitle,
  providerTitle,
  isDirty,
  onSelect,
}: Props) {
  const roots = useMemo(
    () => buildProfileTree(profiles, engineTitle, providerTitle),
    [profiles, engineTitle, providerTitle],
  );
  const selectedNode = useMemo(
    () => findProfileNode(roots, selectedId),
    [roots, selectedId],
  );

  return (
    <Tree<ProfileTreeNode>
      roots={roots}
      ariaLabel="Profiles"
      className="min-h-0 flex-1"
      toolbarClassName="px-2 py-1"
      getKey={(node) => node.key}
      getChildren={(node) => node.children}
      getSearchText={(node) =>
        [node.label, node.key, node.engineTitle, node.provider].filter(Boolean).join(" ")
      }
      getAriaLabel={(node) => profileNodeAriaLabel(node)}
      selected={selectedNode}
      revealSelected
      defaultOpen={(node, depth) =>
        depth === 0 || containsProfile(node, selectedId)
      }
      onSelect={(node) => {
        if (node.profile) onSelect(node.profile);
      }}
      renderRow={({ node, selected }) => (
        <span className="flex min-w-0 flex-1 items-center gap-2">
          <ProfileNodeIcon node={node} selected={selected} />
          <span
            className={`min-w-0 flex-1 truncate ${
              node.type === "profile" ? "" : "font-medium"
            }`}
          >
            {node.label}
          </span>
          {node.profile && isDirty(node.profile) && (
            <span
              className="h-2 w-2 shrink-0 rounded-full bg-amber-500"
              title="Unsaved changes"
            />
          )}
          {node.children.length > 0 && (
            <span className="shrink-0 rounded-full bg-muted px-1.5 py-0.5 text-[10px] tabular-nums text-muted-foreground">
              {profileCount(node)}
            </span>
          )}
        </span>
      )}
      empty={
        <p className="p-3 text-sm text-muted-foreground">No profiles found.</p>
      }
    />
  );
}

function buildProfileTree(
  profiles: Profile[],
  engineTitle: (engine: string) => string,
  providerTitle: (engine: string, provider: string) => string,
): ProfileTreeNode[] {
  return (["discovery", "scan"] as const).flatMap((kind) => {
    const matches = profiles.filter((profile) => profile.kind === kind);
    if (matches.length === 0) return [];

    const engineNames = [...new Set(matches.map((profile) => profile.engine))];
    const children = engineNames
      .map((engine) => {
        const title = engineTitle(engine);
        return {
          key: `${kind}:${engine}`,
          label: title,
          type: "engine" as const,
          kind,
          engineTitle: title,
          icon: engineIcon(engine),
          children: buildEngineChildren(
            matches.filter((profile) => profile.engine === engine),
            title,
            providerTitle,
          ),
        };
      })
      .sort((left, right) => left.label.localeCompare(right.label));

    return [
      {
        key: kind,
        label: kindLabels[kind],
        type: "kind" as const,
        kind,
        children,
      },
    ];
  });
}

function buildEngineChildren(
  profiles: Profile[],
  engineTitle: string,
  providerTitle: (engine: string, provider: string) => string,
): ProfileTreeNode[] {
  const providers = new Map<string, Profile[]>();
  const children: ProfileTreeNode[] = [];

  for (const profile of profiles.sort((left, right) => left.name.localeCompare(right.name))) {
    const provider = profileProvider(profile);
    if (provider) {
      providers.set(provider, [...(providers.get(provider) ?? []), profile]);
    } else {
      children.push(profileNode(profile, engineTitle));
    }
  }

  for (const [provider, matches] of providers) {
    children.push({
      key: `${matches[0].kind}:${matches[0].engine}:provider:${provider}`,
      label: providerTitle(matches[0].engine, provider),
      type: "provider",
      kind: matches[0].kind,
      engineTitle,
      provider,
      icon: providerIcon(provider),
      children: matches.map((profile) => profileNode(profile, engineTitle)),
    });
  }

  return children.sort((left, right) => left.label.localeCompare(right.label));
}

function profileNode(profile: Profile, engineTitle: string): ProfileTreeNode {
  return {
    key: profileId(profile),
    label: profile.name,
    type: "profile",
    kind: profile.kind,
    engineTitle,
    profile,
    children: [],
  };
}

function profileProvider(profile: Profile): string | null {
  const provider = profile.config.provider;
  return typeof provider === "string" && provider !== "" ? provider : null;
}

function engineIcon(engine: string): ElementType {
  return { prowler: UiShield, trivy: Trivy }[engine] ?? UiWrench;
}

function providerIcon(provider: string): ElementType {
  return (
    {
      aws: Aws,
      azure: Azure,
      cloudflare: Cloudflare,
      "container-image": Docker,
      filesystem: UiFolder,
      gcp: Gcp,
      github: Github,
      "git-repository": Git,
      googleworkspace: Google,
      kubernetes: K8S,
      m365: Microsoft,
      mongodbatlas: Mongodb,
      okta: Okta,
      oraclecloud: Oracle,
    }[provider] ?? UiFolder
  );
}

function ProfileNodeIcon({
  node,
  selected,
}: {
  node: ProfileTreeNode;
  selected: boolean;
}) {
  const className = `h-4 w-4 shrink-0 ${
    selected ? "text-primary" : "text-muted-foreground"
  }`;
  if (node.type === "profile") return <UiSliders className={className} />;
  if (node.type === "engine" || node.type === "provider") {
    const NodeIcon = node.icon ?? UiWrench;
    return (
      <span
        role="img"
        aria-label={node.label}
        className="flex h-4 w-4 shrink-0 items-center justify-center"
      >
        <NodeIcon aria-hidden="true" className="h-4 max-w-4" size={16} />
      </span>
    );
  }
  return node.kind === "scan" ? (
    <UiScan className={className} />
  ) : (
    <UiNetwork className={className} />
  );
}

function profileNodeAriaLabel(node: ProfileTreeNode): string {
  if (node.profile) return `${node.label} ${node.engineTitle} profile`;
  return `${node.label} profiles`;
}

function containsProfile(node: ProfileTreeNode, selectedId: string | null): boolean {
  if (!selectedId) return false;
  return (
    node.key === selectedId ||
    node.children.some((child) => containsProfile(child, selectedId))
  );
}

function findProfileNode(
  nodes: ProfileTreeNode[],
  selectedId: string | null,
): ProfileTreeNode | null {
  if (!selectedId) return null;
  for (const node of nodes) {
    if (node.key === selectedId) return node;
    const match = findProfileNode(node.children, selectedId);
    if (match) return match;
  }
  return null;
}

function profileCount(node: ProfileTreeNode): number {
  if (node.profile) return 1;
  return node.children.reduce((count, child) => count + profileCount(child), 0);
}
