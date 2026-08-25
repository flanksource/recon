/**
 * Describes a run-only edit as what it changes about the stored profile.
 *
 * A removed key is sent as null rather than left out. The server layers the
 * override over the profile, so an omitted key means "keep what the profile
 * says" — which is the opposite of what taking an option away means. Choosing
 * one member of a mutually exclusive group removes its siblings, and without
 * the null the profile's member survives the merge and the run fails on a
 * combination nobody asked for.
 */
export function overridePatch(
  base: Record<string, unknown>,
  next: Record<string, unknown>,
): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(next)) {
    if (JSON.stringify(base[key]) !== JSON.stringify(value)) patch[key] = value;
  }
  for (const key of Object.keys(base)) {
    if (!Object.hasOwn(next, key)) patch[key] = null;
  }
  return patch;
}

export function overrideFields(
  field: string,
  value: Record<string, unknown> | undefined,
): Record<string, unknown> {
  return value && Object.keys(value).length > 0 ? { [field]: value } : {};
}

export function scanFileUrl(id: string, name: string): string {
  const encodedPath = name
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  return `/api/scan/${encodeURIComponent(id)}/files/${encodedPath}`;
}
