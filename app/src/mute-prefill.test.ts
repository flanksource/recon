import { describe, expect, it } from "vitest";

import {
  muteCheckPath,
  mutePrefillDraft,
  mutePrefillPath,
  mutePrefillQuery,
  muteScopeOptions,
  suggestMuteName,
} from "./mute-prefill";
import type { Finding } from "./types";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanId: "01JB0000000000000000000000",
    lineNo: 7,
    checkId: "gcp/bucket-public-access",
    name: "Bucket allows public access",
    severity: "high",
    host: "acme-prod",
    matchedAt: "//storage.googleapis.com/acme-logs",
    tags: ["gcp", "storage"],
    resources: [{
      provider: "gcp",
      scope: "acme-prod",
      uid: "projects/acme/buckets/logs",
      name: "acme-logs",
    }],
    ...overrides,
  };
}

describe("mutePrefillQuery", () => {
  it("names only the check, the resource and the engine the scope asked for", () => {
    // Not the tags and severity as well: a rule carrying those would read as
    // "this check on this resource" while quietly meaning something narrower.
    const params = mutePrefillQuery(finding(), "prowler", "check-on-resource");

    expect(Object.fromEntries(params)).toEqual({
      templates: "gcp/bucket-public-access",
      resourceKeys: "gcp/acme-prod/projects/acme/buckets/logs",
      engines: "prowler",
    });
  });

  it("uses the canonical resource key rather than evidence location fields", () => {
    expect(mutePrefillQuery(finding(), undefined, "check-on-resource").get("resourceKeys")).toBe(
      "gcp/acme-prod/projects/acme/buckets/logs",
    );
  });

  it("takes the host when the scope is about the host", () => {
    expect(mutePrefillQuery(finding(), undefined, "check-on-host").get("resources")).toBe(
      "acme-prod",
    );
  });

  it("names no resource at all when the scope is the check everywhere", () => {
    const params = mutePrefillQuery(finding(), undefined, "check-anywhere");

    expect(params.get("templates")).toBe("gcp/bucket-public-access");
    expect(params.has("resources")).toBe(false);
    expect(params.has("resourceKeys")).toBe(false);
  });

  it("names no check when the scope is anything on the resource", () => {
    const params = mutePrefillQuery(finding(), undefined, "anything-on-resource");

    expect(params.has("templates")).toBe(false);
    expect(params.get("resourceKeys")).toBe("gcp/acme-prod/projects/acme/buckets/logs");
  });

  it("does not silently widen a resource scope when canonical identity is missing", () => {
    const params = mutePrefillQuery(finding({ resources: undefined }), undefined, "check-on-resource");
    expect(params.has("resourceKeys")).toBe(false);
    expect(params.has("resources")).toBe(false);
  });

  it("omits the engine when the run's engine is unknown", () => {
    expect(mutePrefillQuery(finding()).has("engines")).toBe(false);
  });
});

describe("muteScopeOptions", () => {
  it("offers the narrowest scope first", () => {
    // The list is read top to bottom by someone deciding how much to hide.
    expect(muteScopeOptions(finding(), "prowler").map((option) => option.id)).toEqual([
      "check-on-resource",
      "check-on-host",
      "check-anywhere",
      "anything-on-resource",
    ]);
  });

  it("says which values each scope resolves to", () => {
    const options = muteScopeOptions(finding());

    expect(options[0].title).toBe("gcp/bucket-public-access on acme-logs");
    expect(options[2].title).toBe("gcp/bucket-public-access anywhere");
  });

  it("omits resource scopes when the finding has no canonical resource", () => {
    const same = finding({
      host: "api.example.test",
      matchedAt: "api.example.test",
      resources: undefined,
    });

    expect(muteScopeOptions(same).map((option) => option.id)).toEqual([
      "check-on-host",
      "check-anywhere",
    ]);
  });

  it("leaves out a scope the finding cannot fill rather than silently widening it", () => {
    // "This check on this resource" with no resource is "this check
    // everywhere", which is a different decision.
    const noResource = finding({ resources: undefined, matchedAt: "", host: "" });

    expect(muteScopeOptions(noResource).map((option) => option.id)).toEqual(["check-anywhere"]);
  });

  it("offers nothing at all for a finding that names neither a check nor a subject", () => {
    expect(muteScopeOptions(finding({ checkId: "", resources: undefined, matchedAt: "", host: "" }))).toEqual([]);
  });

  it("hands back a path the editor can open", () => {
    expect(muteScopeOptions(finding(), "prowler")[2].path).toBe(
      "/mutes/new?templates=gcp%2Fbucket-public-access&engines=prowler",
    );
  });
});

describe("mutePrefillPath", () => {
  it("opens the editor on an unsaved draft", () => {
    expect(mutePrefillPath(finding(), "prowler")).toBe(
      "/mutes/new?templates=gcp%2Fbucket-public-access" +
        "&resourceKeys=gcp%2Facme-prod%2Fprojects%2Facme%2Fbuckets%2Flogs" +
        "&engines=prowler",
    );
  });

  it("still opens the editor when a finding names nothing to select on", () => {
    expect(mutePrefillPath(finding({ checkId: "", resources: undefined, matchedAt: "", host: "" }))).toBe("/mutes/new");
  });
});

describe("mutePrefillDraft", () => {
  // The two halves are one contract: anything the link writes has to survive
  // being read back, or the editor opens describing less than was clicked on.
  it("reads back every dimension the link wrote", () => {
    const query = mutePrefillQuery(finding(), "prowler").toString();

    expect(mutePrefillDraft(`?${query}`)).toEqual({
      name: "",
      templates: ["gcp/bucket-public-access"],
      resourceKeys: ["gcp/acme-prod/projects/acme/buckets/logs"],
      engines: ["prowler"],
    });
  });

  it("splits the comma-separated form a multi-valued dimension travels in", () => {
    expect(mutePrefillDraft("?tags=gcp,storage,public").tags).toEqual(["gcp", "storage", "public"]);
  });

  // An absent dimension is unconstrained on the server. Writing the key as []
  // would make a draft that round-trips differently from one never sent.
  it("leaves a dimension the link did not carry absent rather than empty", () => {
    const draft = mutePrefillDraft("?templates=open-redirect");

    expect(draft).toEqual({ name: "", templates: ["open-redirect"] });
    expect("tags" in draft).toBe(false);
  });

  it("never takes the rule's name from the link", () => {
    expect(mutePrefillDraft("?name=already-accepted&templates=x").name).toBe("");
  });

  it("opens an empty draft when the link carried no query at all", () => {
    expect(mutePrefillDraft("")).toEqual({ name: "" });
  });
});

describe("suggestMuteName", () => {
  it("names a rule after the check and the resource it covers", () => {
    const name = suggestMuteName({
      name: "",
      templates: ["gcp/bucket-public-access"],
      resourceKeys: ["gcp/acme-prod/projects/acme/buckets/logs"],
    });

    expect(name).toBe("gcp-bucket-public-access-logs");
  });

  it("produces a name the server's own pattern accepts", () => {
    // mute_rules_name_format: ^[a-z0-9][a-z0-9-]*$
    const name = suggestMuteName({
      name: "",
      templates: ["CVE-2018-15811"],
      resources: ["https://api.example.test/dnn?q=1"],
    });

    expect(name).toMatch(/^[a-z0-9][a-z0-9-]*$/);
    expect(name).toBe("cve-2018-15811-dnn");
  });

  it("names a check-wide rule after the check alone", () => {
    expect(suggestMuteName({ name: "", templates: ["open-redirect"] })).toBe("open-redirect");
  });

  it("falls back to a tag, then a severity, when there is no check or resource", () => {
    expect(suggestMuteName({ name: "", tags: ["!dos", "redirect"] })).toBe("redirect");
    expect(suggestMuteName({ name: "", severity: ["high"] })).toBe("high");
  });

  it("still names a rule that selects on nothing nameable", () => {
    expect(suggestMuteName({ name: "", expr: "finding.host == 'x'" })).toBe("muted-finding");
  });

  it("does not reuse a name that already exists", () => {
    // The server upserts on the name, so a collision would rewrite that rule
    // instead of adding one.
    const rule = { name: "", templates: ["open-redirect"] };

    expect(suggestMuteName(rule, ["open-redirect"])).toBe("open-redirect-2");
    expect(suggestMuteName(rule, ["open-redirect", "open-redirect-2"])).toBe("open-redirect-3");
  });
});

describe("muteCheckPath", () => {
  it("writes the same rule the check-anywhere scope does", () => {
    // The check page has no finding to seed from, so it builds the draft from
    // the check and the engine directly. The two must not drift: if the scope
    // ever gains a dimension, this is what says so.
    expect(muteCheckPath("gcp/bucket-public-access", "prowler")).toBe(
      mutePrefillPath(finding(), "prowler", "check-anywhere"),
    );
  });

  it("is independent of which affected resource it was reached from", () => {
    const other = finding({
      host: "other-account",
      matchedAt: "//storage.googleapis.com/other-bucket",
      resources: [{ provider: "gcp", scope: "other-account", uid: "other-bucket" }],
    });

    expect(mutePrefillPath(other, "prowler", "check-anywhere"))
      .toBe(muteCheckPath("gcp/bucket-public-access", "prowler"));
  });

  it("still opens the editor when there is no engine to scope to", () => {
    expect(muteCheckPath("gcp/bucket-public-access")).toBe(
      "/mutes/new?templates=gcp%2Fbucket-public-access",
    );
  });
});
