// The mute listing's client. Separate from api.ts because that file is already
// at the size the repo splits at; it shares the same fetch helpers, so there is
// one way of reaching the API rather than two.

import { json, query, request } from "./api-client";
import type { MutePreview, MuteRule } from "./mute-types";

const API = "/api/v1";

export function fetchMutes(params?: {
  engine?: string;
  severity?: string;
  template?: string;
  disabled?: boolean;
}): Promise<MuteRule[]> {
  return request<MuteRule[]>(`${API}/mute${query(params)}`);
}

export function fetchMute(name: string): Promise<MuteRule> {
  return request<MuteRule>(`${API}/mute/${encodeURIComponent(name)}`);
}

/**
 * The fields a rule is written with.
 *
 * Named rather than spread. A listing stamps `_id` onto every row it returns
 * and the server decodes a write with DisallowUnknownFields, so spreading the
 * rule the editor is holding turns "save the rule you clicked in the list" into
 * `unknown field "_id"`. createdAt and updatedAt are the server's to set and
 * would fail the same way.
 *
 * An absent field is left out rather than sent as null: on the server an empty
 * dimension is unconstrained, and every one of these is optional.
 */
function muteBody(rule: MuteRule): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  const carry = (field: keyof MuteRule) => {
    if (rule[field] !== undefined) body[field] = rule[field];
  };

  carry("comment");
  carry("disabled");
  carry("engines");
  carry("targets");
  carry("resources");
  carry("resourceKeys");
  carry("templates");
  carry("tags");
  carry("severity");
  carry("expr");

  return body;
}

export function createMute(rule: MuteRule): Promise<MuteRule> {
  return request<MuteRule>(`${API}/mute`, json("POST", { name: rule.name, ...muteBody(rule) }));
}

/**
 * Updates a rule in place.
 *
 * The name travels as `id` because that is the address the entity framework
 * routes on, and `name` is not sent at all: a rule cannot be renamed, or the
 * runs citing the old name in their mutes.json would point at nothing.
 */
export function updateMute(name: string, rule: MuteRule): Promise<MuteRule> {
  return request<MuteRule>(`${API}/mute`, json("PUT", { id: name, ...muteBody(rule) }));
}

export function deleteMute(name: string): Promise<void> {
  return request<void>(`${API}/mute/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
}

/**
 * Reports what a rule would have taken out of runs that already finished.
 *
 * This is the only way to see a rule's reach: a rule in force drops what it
 * matches rather than marking it, so once it is saved there is nothing left to
 * inspect. It can only speak for findings earlier runs kept.
 */
export function previewMute(
  name: string,
  params?: { scan?: string; limit?: number },
): Promise<MutePreview> {
  return request<MutePreview>(
    `${API}/mute/${encodeURIComponent(name)}/preview${query(params)}`,
    { method: "POST" },
  );
}
