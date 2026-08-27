import type { ComponentType } from "react";
import type { FindingBadge } from "@flanksource/facet";
import {
  UiBug,
  UiClock,
  UiCloud,
  UiDatabase,
  UiExternalLink,
  UiEye,
  UiFileCog,
  UiFilter,
  UiGitBranch,
  UiGlobe,
  UiInfo,
  UiKey,
  UiListChecks,
  UiLockKey,
  UiNetwork,
  UiPackage,
  UiQuestion,
  UiScan,
  UiSealCheck,
  UiServer,
  UiShieldCheck,
  UiShieldCross,
  UiShieldWarning,
  UiSiren,
  UiTag,
  UiUser,
  UiUsersThree,
  UiWarningCircle,
  UiWarningTriangle,
  UiWrench,
} from "@flanksource/clicky-ui/icons";

import { SEVERITY_BADGE, type FindingGroup, type MetadataKind } from "./scan-report-model";
import type { ReportSeverity } from "./scan-report-types";

export type BadgeIcon = ComponentType<{ className?: string }>;

/**
 * A hue and a glyph for one idea — the whole styling currency of the report.
 *
 * One shape rather than a `{ category, icon }` discriminator because severity
 * does not draw from `CATEGORY_CLASS`: it has its own ramp, and a category name
 * cannot express it. Callers that need a colour and a glyph — badges, the
 * cover's tiles, the breakdown icon columns — all take this.
 */
export type TagStyle = { className: string; icon: BadgeIcon };

type BadgeCategory =
  | "identity"
  | "integrity"
  | "confidential"
  | "audit"
  | "threat"
  | "stage"
  | "control"
  | "infra"
  | "asset"
  | "risk"
  | "action"
  | "neutral";

export const CATEGORY_CLASS: Record<BadgeCategory, string> = {
  identity: "bg-violet-50 text-violet-700 border-violet-200",
  integrity: "bg-amber-50 text-amber-800 border-amber-200",
  confidential: "bg-indigo-50 text-indigo-700 border-indigo-200",
  audit: "bg-sky-50 text-sky-700 border-sky-200",
  threat: "bg-rose-50 text-rose-700 border-rose-200",
  stage: "bg-blue-50 text-blue-700 border-blue-200",
  control: "bg-emerald-50 text-emerald-700 border-emerald-200",
  infra: "bg-teal-50 text-teal-700 border-teal-200",
  asset: "bg-cyan-50 text-cyan-700 border-cyan-200",
  risk: "bg-amber-50 text-amber-800 border-amber-300",
  action: "bg-indigo-50 text-indigo-700 border-indigo-200",
  neutral: "bg-slate-100 text-slate-700 border-slate-300",
};

function style(category: BadgeCategory, icon: BadgeIcon): TagStyle {
  return { className: CATEGORY_CLASS[category], icon };
}

/**
 * The word that decides a label's hue and glyph.
 *
 * `/` is a word boundary alongside `-` and `:` so a check id reads as a phrase
 * — `exposures/files/directory-listing` is about exposure, not about a slash —
 * and a trailing `s` is optional because a path segment names a family
 * (`exposures`, `configs`) where a tag names one thing (`exposure`).
 */
const TAG_STYLES: Array<{ match: RegExp; style: TagStyle }> = [
  {
    match: /(^|[-:/])(secret|credential|password|token|key)s?([-:/]|$)/,
    style: style("integrity", UiKey),
  },
  {
    match: /(^|[-:/])(identity|iam|auth|sso|user|role|permission)s?([-:/]|$)/,
    style: style("identity", UiUsersThree),
  },
  {
    match: /(^|[-:/])(vulnerability|vulnerable|cve|exploit|malware|threat)s?([-:/]|$)/,
    style: style("threat", UiBug),
  },
  {
    match: /(^|[-:/])(exposure|exposed|disclosure|public)s?([-:/]|$)/,
    style: style("confidential", UiEye),
  },
  {
    match: /(^|[-:/])(git|source|scm|repository|repo)s?([-:/]|$)/,
    style: style("stage", UiGitBranch),
  },
  {
    match: /(^|[-:/])(dependency|dependencies|package|artifact|image|container|registry)s?([-:/]|$)/,
    style: style("stage", UiPackage),
  },
  {
    match: /(^|[-:/])(tls|ssl|certificate|encryption|crypto)s?([-:/]|$)/,
    style: style("control", UiLockKey),
  },
  {
    match: /(^|[-:/])(network|dns|http|ingress|egress|firewall|port)s?([-:/]|$)/,
    style: style("infra", UiNetwork),
  },
  {
    match: /(^|[-:/])(cloud|aws|azure|gcp|kubernetes|k8s|infrastructure|infra)s?([-:/]|$)/,
    style: style("infra", UiCloud),
  },
  {
    match: /(^|[-:/])(database|db|storage|bucket|s3|rds)s?([-:/]|$)/,
    style: style("asset", UiDatabase),
  },
  {
    match: /(^|[-:/])(audit|logging|log|cis|nist|iso|pci)s?([-:/]|$)/,
    style: style("audit", UiListChecks),
  },
  {
    match: /(^|[-:/])(misconfig|misconfiguration|risk|unsafe)s?([-:/]|$)/,
    style: style("risk", UiWarningTriangle),
  },
  {
    match: /(^|[-:/])(policy|control|guardrail|secure|hardening)s?([-:/]|$)/,
    style: style("control", UiShieldCheck),
  },
  {
    match: /(^|[-:/])(remediation|action|fix)s?([-:/]|$)/,
    style: style("action", UiWrench),
  },
  {
    match: /(^|[-:/])(config|configuration|setting)s?([-:/]|$)/,
    style: style("asset", UiFileCog),
  },
];

function normalize(label: string): string {
  return label.trim().toLowerCase().replaceAll("_", "-");
}

function matchTagStyle(value: string): TagStyle | undefined {
  return value ? TAG_STYLES.find((candidate) => candidate.match.test(value))?.style : undefined;
}

export function tagStyle(label: string): TagStyle {
  return matchTagStyle(normalize(label)) ?? style("asset", UiTag);
}

export function typeStyle(label: string): TagStyle {
  const normalized = normalize(label);
  if (normalized === "http") return style("infra", UiGlobe);
  if (normalized === "dns") return style("infra", UiNetwork);
  if (["ssl", "tls"].includes(normalized)) return style("control", UiLockKey);
  return style("control", UiScan);
}

export function severityStyle(severity: string): TagStyle {
  const key = (severity in SEVERITY_ICON ? severity : "unknown") as ReportSeverity;
  return { className: SEVERITY_BADGE[key], icon: SEVERITY_ICON[key] };
}

export function resourceStyle(name: string): TagStyle {
  return { className: CATEGORY_CLASS.infra, icon: resourceInstanceIcon(name) };
}

/**
 * What a check is about, read past the wire family it belongs to.
 *
 * `http/` prefixes almost every template a web scanner ships, so matching the
 * whole id gives a page of breakdown rows one glyph. The family is the fallback
 * rather than the answer: it only decides the icon when nothing after it does.
 */
export function checkStyle(templateId: string): TagStyle {
  const [family, ...rest] = normalize(templateId).split("/");
  return matchTagStyle(rest.join("/")) ?? matchTagStyle(family) ?? typeStyle(family);
}

function badge(label: string, tag: TagStyle): FindingBadge {
  return { label, className: tag.className, icon: tag.icon };
}

function tagBadge(label: string): FindingBadge {
  return badge(label, tagStyle(label));
}

function statusCodeBadge(label: string): FindingBadge {
  const normalized = normalize(label);
  if (["fail", "failed", "error"].includes(normalized)) {
    return badge(label, style("threat", UiShieldCross));
  }
  if (["pass", "passed", "success"].includes(normalized)) {
    return badge(label, style("control", UiShieldCheck));
  }
  return badge(label, style("audit", UiListChecks));
}

function engineBadge(label: string): FindingBadge {
  return badge(label, typeStyle(label));
}

/**
 * Run detail, tiled by what each row is about: blue is the instrument, emerald
 * the check set and a clean verdict, cyan what was in scope, slate when, violet
 * who, sky where the record lives, amber a run that did not finish.
 *
 * `mono` marks the values that are identifiers rather than prose — a profile
 * key and a URL are copied character by character, an audience is read.
 */
export const METADATA_STYLE: Record<MetadataKind, TagStyle & { mono: boolean }> = {
  engine: { ...style("stage", UiScan), mono: true },
  profile: { ...style("control", UiListChecks), mono: true },
  selector: { ...style("asset", UiFilter), mono: true },
  time: { ...style("neutral", UiClock), mono: true },
  outcome: { ...style("control", UiSealCheck), mono: false },
  incomplete: { ...style("risk", UiWarningTriangle), mono: false },
  audience: { ...style("identity", UiUsersThree), mono: false },
  author: { ...style("identity", UiUser), mono: false },
  source: { ...style("audit", UiExternalLink), mono: true },
  classification: { ...style("audit", UiShieldCheck), mono: false },
};

export function findingBadges(group: FindingGroup): FindingBadge[] {
  const seen = new Set<string>();
  const badges: FindingBadge[] = [];
  const push = (candidate: FindingBadge) => {
    const key = candidate.label.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    badges.push(candidate);
  };
  group.statusCodes.map(statusCodeBadge).forEach(push);
  group.engines.map(engineBadge).forEach(push);
  group.tags.map(tagBadge).forEach(push);
  return badges;
}

export function findingTypeIcon(group: FindingGroup): BadgeIcon {
  return group.engines.length > 0 ? typeStyle(group.engines[0]).icon : UiScan;
}

export function resourceInstanceIcon(type: string): BadgeIcon {
  const normalized = type.trim().toLowerCase();
  if (/(serviceaccount|identity|iam|user|role)/.test(normalized)) return UiUsersThree;
  if (/(database|sql|rds|storage|bucket)/.test(normalized)) return UiDatabase;
  if (/(package|artifact|container|image|registry)/.test(normalized)) return UiPackage;
  if (/(dns|network|ingress|egress|firewall)/.test(normalized)) return UiNetwork;
  if (/(http|url|website|domain)/.test(normalized)) return UiGlobe;
  if (/(cloud|kubernetes|k8s)/.test(normalized)) return UiCloud;
  return UiServer;
}

const SEVERITY_ICON: Record<ReportSeverity, BadgeIcon> = {
  critical: UiSiren,
  high: UiShieldWarning,
  medium: UiWarningTriangle,
  low: UiWarningCircle,
  info: UiInfo,
  unknown: UiQuestion,
};

export function severityBadge(severity: ReportSeverity): FindingBadge {
  return badge(severity, severityStyle(severity));
}
