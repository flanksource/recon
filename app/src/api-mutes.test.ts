import { afterEach, describe, expect, it, vi } from "vitest";

import { createMute, updateMute } from "./api-mutes";
import type { MuteRule } from "./mute-types";

afterEach(() => vi.restoreAllMocks());

function respond(rule: Partial<MuteRule> = {}) {
  return vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(
      new Response(JSON.stringify({ name: "accepted-logs-bucket", ...rule }), { status: 200 }),
    );
}

function sentBody(mock: ReturnType<typeof respond>): Record<string, unknown> {
  const [, init] = mock.mock.calls[0] as [string, RequestInit];
  return JSON.parse(String(init.body)) as Record<string, unknown>;
}

// A rule as it comes back from the listing: the server stamps `_id` onto rows
// in a list response, so this is the shape the editor actually holds after
// someone clicks a rule, not a hypothetical one.
const LISTED: MuteRule = {
  _id: "accepted-logs-bucket",
  name: "accepted-logs-bucket",
  comment: "Log bucket is public by design",
  templates: ["gcp/bucket-public-access"],
  severity: ["high"],
  createdAt: "2026-08-20T09:00:00Z",
  updatedAt: "2026-08-20T09:00:00Z",
};

describe("mute API", () => {
  it("does not send the row key the listing stamped back to the server", async () => {
    // The server decodes with DisallowUnknownFields, so a stray `_id` is a
    // rejected save rather than an ignored field: editing any rule reached
    // through the list would fail with `unknown field "_id"`.
    const fetchMock = respond();

    await updateMute("accepted-logs-bucket", LISTED);

    expect(sentBody(fetchMock)).not.toHaveProperty("_id");
  });

  it("does not send the timestamps the server owns", async () => {
    const fetchMock = respond();

    await updateMute("accepted-logs-bucket", LISTED);

    const body = sentBody(fetchMock);
    expect(body).not.toHaveProperty("createdAt");
    expect(body).not.toHaveProperty("updatedAt");
  });

  it("addresses an update by id in the body, never by a renamed rule", async () => {
    // A rename would orphan the runs citing the old name in their mutes.json,
    // so the address comes from the path argument and `name` is not sent.
    const fetchMock = respond();

    await updateMute("accepted-logs-bucket", { ...LISTED, name: "something-else" });

    const body = sentBody(fetchMock);
    expect(body.id).toBe("accepted-logs-bucket");
    expect(body).not.toHaveProperty("name");
  });

  it("sends every dimension the rule selects on", async () => {
    const fetchMock = respond();

    await updateMute("accepted-logs-bucket", {
      ...LISTED,
      disabled: true,
      engines: ["prowler"],
      targets: { class: ["non-prod"] },
      resources: ["//storage.googleapis.com/acme-logs"],
      tags: ["storage", "!dos"],
      expr: 'finding.host == "acme-prod"',
    });

    expect(sentBody(fetchMock)).toEqual({
      id: "accepted-logs-bucket",
      comment: "Log bucket is public by design",
      disabled: true,
      engines: ["prowler"],
      targets: { class: ["non-prod"] },
      resources: ["//storage.googleapis.com/acme-logs"],
      templates: ["gcp/bucket-public-access"],
      tags: ["storage", "!dos"],
      severity: ["high"],
      expr: 'finding.host == "acme-prod"',
    });
  });

  it("creates a rule under the name that was typed", async () => {
    const fetchMock = respond();

    await createMute({ name: "new-rule", templates: ["gcp/*"] });

    expect(sentBody(fetchMock)).toEqual({ name: "new-rule", templates: ["gcp/*"] });
  });

  it("does not carry a listed rule's key into a create either", async () => {
    // Reachable by seeding a new rule from an existing one, and the failure
    // would look identical.
    const fetchMock = respond();

    await createMute({ ...LISTED, name: "copied-rule" });

    expect(sentBody(fetchMock)).not.toHaveProperty("_id");
  });
});
