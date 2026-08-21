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
