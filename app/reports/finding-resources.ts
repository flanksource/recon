import type { ReportFinding } from "./scan-report-types";

export type FindingResourceInstance = {
  name: string;
  region: string;
  type: string;
  uid: string;
};

function resourceField(
  finding: ReportFinding,
  resource: Record<string, unknown>,
  key: keyof FindingResourceInstance,
): string {
  const value = resource[key];
  if (value == null) return "";
  if (typeof value !== "string") {
    throw new Error(`${finding.scanId}#${finding.lineNo} resource.${key} must be a string`);
  }
  return value;
}

export function findingResourceInstances(finding: ReportFinding): FindingResourceInstance[] {
  const rawResources = finding.raw?.resources;
  if (rawResources == null || (Array.isArray(rawResources) && rawResources.length === 0)) {
    return [
      {
        name: finding.matchedAt || finding.host,
        region: "",
        type: finding.type ?? "",
        uid: finding.host,
      },
    ];
  }
  if (!Array.isArray(rawResources)) {
    throw new Error(`${finding.scanId}#${finding.lineNo} raw.resources must be an array`);
  }
  return rawResources.map((resource, index) => {
    if (!resource || typeof resource !== "object" || Array.isArray(resource)) {
      throw new Error(`${finding.scanId}#${finding.lineNo} raw.resources[${index}] must be an object`);
    }
    const record = resource as Record<string, unknown>;
    return {
      name: resourceField(finding, record, "name"),
      region: resourceField(finding, record, "region"),
      type: resourceField(finding, record, "type"),
      uid: resourceField(finding, record, "uid"),
    };
  });
}

export function uniqueFindingResourceInstances(
  findings: ReportFinding[],
): FindingResourceInstance[] {
  const instances = new Map<string, FindingResourceInstance>();
  findings.flatMap(findingResourceInstances).forEach((instance) => {
    instances.set(JSON.stringify(instance), instance);
  });
  return [...instances.values()].sort(
    (left, right) =>
      left.name.localeCompare(right.name) ||
      left.region.localeCompare(right.region) ||
      left.type.localeCompare(right.type) ||
      left.uid.localeCompare(right.uid),
  );
}
