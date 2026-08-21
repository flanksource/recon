import type { Severity } from "./types";

export type TemplateRemediationMetadata = {
  text?: string;
  url?: string;
  code?: Record<string, string>;
};

export type TemplateMetadata = {
  aliases?: string[];
  subService?: string;
  resourceGroup?: string;
  resourceIdTemplate?: string;
  categories?: string[];
  checkTypes?: string[];
  remediation?: TemplateRemediationMetadata;
  dependsOn?: string[];
  relatedTo?: string[];
  notes?: string;
  [key: string]: unknown;
};

export type Template = {
  _id?: string;
  id: string;
  name: string;
  engine: string;
  provider?: string;
  severity: Severity;
  type: string;
  tags: string[];
  authors: string[];
  path: string;
  description?: string;
  risk?: string;
  resourceType?: string;
  remediation?: string;
  reference?: string[];
  cveId?: string;
  cvssScore?: number;
  maxRequests?: number;
  requires?: string[];
  metadata?: TemplateMetadata;
};

export type TemplateTag = { tag: string; count: number };

export type TemplatePreview = {
  engine: string;
  profile?: string;
  total: number;
  bySeverity: Partial<Record<Severity, number>>;
  byType: Record<string, number>;
  byTag: TemplateTag[];
  maxRequests: number;
  templates: Template[];
  truncated: boolean;
  caveats?: string[];
};
