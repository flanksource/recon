type ExecutorFailure = { success?: boolean; error?: string; message?: string };

export async function request<T>(
  path: string,
  init?: RequestInit,
  ...rest: never[]
): Promise<T> {
  void rest;
  const method = init?.method ?? "GET";
  const response = await fetch(path, init);

  let body: unknown = null;
  const text = await response.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(
        `${method} ${path} returned invalid JSON: ${text.slice(0, 200)}`,
      );
    }
  }

  const failure = body as ExecutorFailure | null;
  if (!response.ok) {
    throw new Error(
      failure?.error ??
        failure?.message ??
        `${method} ${path} failed: ${response.status}`,
    );
  }
  if (failure && typeof failure === "object" && failure.success === false) {
    throw new Error(
      failure.error ?? failure.message ?? `${method} ${path} failed`,
    );
  }
  return body as T;
}

export function query(params: Record<string, unknown> | undefined): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (
      value === undefined ||
      value === null ||
      value === "" ||
      value === false
    ) {
      continue;
    }
    search.set(key, Array.isArray(value) ? value.join(",") : String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : "";
}

export function json(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}
