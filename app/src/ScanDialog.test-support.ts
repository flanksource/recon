import { vi } from "vitest";
import type { Engine, Profile, Scan, TargetRow, TemplatePreview } from "./types";

export const rows: TargetRow[] = [
  {
    $schema: "../target.schema.json",
    version: 1,
    id: "api.example.com",
    host: "api.example.com",
    class: "non-prod",
    profiles: ["scan:nuclei:safe"],
    tags: ["api"],
  },
  {
    $schema: "../target.schema.json",
    version: 1,
    id: "docs.example.com",
    host: "docs.example.com",
    class: "public",
    profiles: ["scan:nuclei:safe"],
    tags: ["docs"],
  },
];

export const nucleiEngine: Engine = {
  _id: "scan:nuclei",
  name: "nuclei",
  kind: "scan",
  title: "Nuclei",
  binary: "nuclei",
  installed: true,
  managed: true,
  options: {
    variants: [
      {
        id: "default",
        title: "Nuclei",
        schema: {
          type: "object",
          "x-sections": [{ id: "scan", title: "Scan" }],
          "x-order": ["dast"],
          properties: {
            dast: { type: "boolean", title: "DAST", "x-section": "scan" },
          },
        },
      },
    ],
  },
};

// Prowler declares one argparse choice over five options, so a run that moves
// from a compliance framework to a service list has to take the framework away.
export const prowlerEngine: Engine = {
  _id: "scan:prowler",
  name: "prowler",
  kind: "scan",
  title: "Prowler",
  binary: "prowler",
  installed: true,
  managed: true,
  options: {
    discriminator: "provider",
    variants: [
      {
        id: "github",
        title: "GitHub",
        schema: {
          type: "object",
          "x-sections": [{ id: "selection", title: "Specify checks/services to run" }],
          "x-order": ["provider", "compliance", "services"],
          "x-mutual-exclusions": [
            {
              id: "common-mutex-1",
              title: "Specify checks/services to run",
              keys: ["compliance", "services"],
            },
          ],
          properties: {
            provider: { type: "string", const: "github", "x-section": "selection" },
            compliance: {
              type: "array",
              title: "Compliance",
              "x-section": "selection",
              items: { type: "string", enum: ["cis_1.0_github"] },
            },
            services: {
              type: "array",
              title: "Services",
              "x-section": "selection",
              items: { type: "string", enum: ["organization", "repository"] },
            },
          },
        },
      },
    ],
  },
};

export const complianceProfile: Profile = {
  _id: "scan:prowler:github-cis-1-0-github",
  kind: "scan",
  engine: "prowler",
  name: "github-cis-1-0-github",
  config: { provider: "github", compliance: ["cis_1.0_github"] },
  intrusive: false,
};

export const naabuEngine: Engine = {
  _id: "discovery:naabu",
  name: "naabu",
  kind: "discovery",
  title: "Naabu",
  binary: "naabu",
  installed: true,
  managed: true,
  options: {
    variants: [
      {
        id: "default",
        title: "Naabu",
        schema: {
          type: "object",
          "x-sections": [{ id: "ports", title: "Ports" }],
          "x-order": ["top-ports"],
          properties: {
            "top-ports": {
              type: "string",
              title: "Top ports",
              "x-section": "ports",
            },
          },
        },
      },
    ],
  },
};

export const discoveryProfiles: Profile[] = [
  {
    _id: "discovery:naabu:default",
    kind: "discovery",
    engine: "naabu",
    name: "default",
    config: { "top-ports": "100" },
  },
  {
    _id: "discovery:naabu:full-ports",
    kind: "discovery",
    engine: "naabu",
    name: "full-ports",
    config: { "top-ports": "65535" },
  },
];

export const safeProfile: Profile = {
  _id: "scan:nuclei:safe",
  kind: "scan",
  engine: "nuclei",
  name: "safe",
  config: {},
  intrusive: false,
};

export const intrusiveProfile: Profile = {
  _id: "scan:nuclei:full",
  kind: "scan",
  engine: "nuclei",
  name: "full",
  config: { dast: true },
  intrusive: true,
  reason: "DAST sends active payloads",
};

export const templatePreview: TemplatePreview = {
  engine: "nuclei",
  total: 4314,
  bySeverity: { critical: 96, high: 803 },
  byType: { http: 4314 },
  byTag: [{ tag: "panel", count: 1200 }],
  maxRequests: 9000,
  templates: [],
  truncated: true,
};

export const createdScan: Scan = {
  _id: "scan-1",
  id: "scan-1",
  name: "run-1",
  engine: "nuclei",
  profile: "safe",
  selector: { hosts: ["api.example.com"] },
  selectorLabel: "hosts api.example.com",
  endpointCount: 1,
  phase: "running",
  startedAt: "2026-08-09T08:00:00.000Z",
  durationMs: 0,
  findings: 0,
  severities: {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    unknown: 0,
  },
  hosts: ["api.example.com"],
};

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

export function mockFetch(handlers: Record<string, unknown>) {
  const routes: Record<string, unknown> = {
    "/api/v1/engine?kind=discovery": [naabuEngine],
    "/api/v1/profile?kind=discovery": discoveryProfiles,
    "/api/template/preview": templatePreview,
    "/api/v1/template": { filters: {} },
    ...handlers,
  };
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = typeof input === "string" ? input : (input as Request).url;
    const path = url.replace(/^https?:\/\/[^/]+/, "");
    const match = Object.entries(routes).find(([prefix]) => path.startsWith(prefix));
    if (!match) throw new Error(`unexpected fetch: ${path}`);
    const body = match[1];
    return jsonResponse(
      typeof body === "function"
        ? (body as (path: string, init?: RequestInit) => unknown)(path, init)
        : body,
    );
  });
}
