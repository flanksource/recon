import type { ReportFinding, ReportResourceRef } from "./scan-report-types";

export type FindingResourceInstance = {
  name: string;
  region: string;
  type: string;
  uid: string;
};

/**
 * The resources a finding names.
 *
 * This used to reach into `finding.raw.resources[]` and reconstruct the shape
 * itself, because the API had nowhere to put a resource. It is a projection of
 * the typed field now: the server reads the engine's record, including for the
 * engines that name no resource of their own, so there is one implementation of
 * "what is this finding about" rather than one here and a different one in Go.
 */
export function findingResourceInstances(finding: ReportFinding): FindingResourceInstance[] {
  return (finding.resources ?? []).map(instance);
}

function instance(resource: ReportResourceRef): FindingResourceInstance {
  return {
    name: resource.name ?? "",
    region: resource.region ?? "",
    type: resource.type ?? "",
    uid: resource.uid,
  };
}

export function uniqueFindingResourceInstances(
  findings: ReportFinding[],
): FindingResourceInstance[] {
  const instances = new Map<string, FindingResourceInstance>();
  findings.flatMap(findingResourceInstances).forEach((entry) => {
    instances.set(JSON.stringify(entry), entry);
  });
  return [...instances.values()].sort(
    (left, right) =>
      left.name.localeCompare(right.name) ||
      left.region.localeCompare(right.region) ||
      left.type.localeCompare(right.type) ||
      left.uid.localeCompare(right.uid),
  );
}
