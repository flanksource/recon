import {
  UiBug,
  UiEye,
  UiGitBranch,
  UiKey,
  UiLockKey,
  UiNetwork,
  UiSiren,
  UiTag,
  UiUsersThree,
  UiWarningTriangle,
} from "@flanksource/clicky-ui/icons";
import { describe, expect, it } from "vitest";

import { groupFindings, type MetadataKind } from "./scan-report-model";
import {
  METADATA_STYLE,
  checkStyle,
  findingBadges,
  resourceInstanceIcon,
  resourceStyle,
  severityStyle,
  tagStyle,
} from "./scan-report-tags";
import type { ReportFinding } from "./scan-report-types";

const FINDING: ReportFinding = {
  scanId: "scan-1",
  lineNo: 1,
  checkId: "supply-chain-check",
  engine: "nuclei",
  host: "repo.example.test",
  matchedAt: "repo.example.test",
  severity_id: 4,
  status_code: "FAIL",
  finding_info: { uid: "supply-chain-check", title: "Supply chain finding" },
  tags: [
    "identity",
    "leaked-secret",
    "vulnerability",
    "git",
    "unclassified-label",
    "compliance:CIS-1.2",
  ],
};

describe("findingBadges", () => {
  it("filters compliance metadata and gives every remaining label a semantic icon and color", () => {
    const badges = findingBadges(groupFindings([FINDING])[0]);
    const byLabel = new Map(badges.map((badge) => [badge.label, badge]));

    expect([...byLabel.keys()]).toEqual([
      "FAIL",
      "nuclei",
      "identity",
      "leaked-secret",
      "vulnerability",
      "git",
      "unclassified-label",
    ]);
    expect(byLabel.get("identity")).toMatchObject({
      className: expect.stringContaining("text-violet-700"),
      icon: UiUsersThree,
    });
    expect(byLabel.get("leaked-secret")).toMatchObject({
      className: expect.stringContaining("text-amber-800"),
      icon: UiKey,
    });
    expect(byLabel.get("vulnerability")).toMatchObject({
      className: expect.stringContaining("text-rose-700"),
      icon: UiBug,
    });
    expect(byLabel.get("git")).toMatchObject({
      className: expect.stringContaining("text-blue-700"),
      icon: UiGitBranch,
    });
    expect(byLabel.get("unclassified-label")).toMatchObject({
      className: expect.stringContaining("text-cyan-700"),
      icon: UiTag,
    });
    expect(byLabel.has("compliance:CIS-1.2")).toBe(false);
  });

  it("uses the identity glyph for service-account instances", () => {
    expect(resourceInstanceIcon("iam.googleapis.com/ServiceAccount")).toBe(UiUsersThree);
  });
});

describe("checkStyle", () => {
  // Every check a network scanner emits shares its wire prefix, so keying the
  // glyph off `http` would give a whole page of breakdown rows one icon. What
  // the check is *about* lives in the rest of the path.
  it.each([
    ["http/misconfiguration/missing-csp", UiWarningTriangle],
    ["http/misconfiguration/cookies-without-secure", UiWarningTriangle],
    ["http/exposures/files/directory-listing", UiEye],
    ["http/technologies/version-disclosure", UiEye],
    ["ssl/expired-certificate", UiLockKey],
    // The most specific fact in the path wins: this check is about credentials
    // that exist, not about identity in general.
    ["gcp/iam_service_account_keys", UiKey],
    ["aws/iam_root_mfa", UiUsersThree],
  ])("reads %s past its wire prefix", (templateId, icon) => {
    expect(checkStyle(templateId).icon).toBe(icon);
  });

  it("falls back to the wire family when the rest of the path says nothing", () => {
    expect(checkStyle("dns/caa-fingerprint").icon).toBe(UiNetwork);
  });

  it("does not mistake a path segment for a repository", () => {
    expect(checkStyle("http/exposures/configs/git-config").icon).not.toBe(UiGitBranch);
  });
});

describe("severityStyle", () => {
  it("gives a severity its own ramp rather than a category hue", () => {
    expect(severityStyle("critical")).toEqual({
      className: expect.stringContaining("text-rose-700"),
      icon: UiSiren,
    });
  });
});

describe("resourceStyle", () => {
  it("tiles a resource in the infrastructure hue with its own glyph", () => {
    expect(resourceStyle("iam.googleapis.com/ServiceAccount")).toEqual({
      className: expect.stringContaining("text-teal-700"),
      icon: UiUsersThree,
    });
  });
});

describe("tagStyle", () => {
  it("still resolves a label once path separators are matchable", () => {
    expect(tagStyle("exposures/files").icon).toBe(UiEye);
    expect(tagStyle("unclassified-label").icon).toBe(UiTag);
  });
});

describe("METADATA_STYLE", () => {
  const KINDS: MetadataKind[] = [
    "engine",
    "profile",
    "selector",
    "time",
    "outcome",
    "incomplete",
    "audience",
    "author",
    "source",
    "classification",
  ];

  it("gives every run-detail kind a hue, a glyph and a verdict on monospace", () => {
    for (const kind of KINDS) {
      expect(METADATA_STYLE[kind], kind).toMatchObject({
        className: expect.stringMatching(/text-\w+-\d{3}/),
        icon: expect.any(Function),
        mono: expect.any(Boolean),
      });
    }
  });

  it("reserves the warning hue for a run that did not finish", () => {
    expect(METADATA_STYLE.outcome.className).toContain("text-emerald-700");
    expect(METADATA_STYLE.incomplete.className).toContain("text-amber-800");
  });
});
