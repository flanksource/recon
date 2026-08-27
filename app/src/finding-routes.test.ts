import { describe, expect, it } from "vitest";
import { findingGroupHref, parseCheckId } from "./finding-routes";

describe("finding-routes", () => {
  it("keeps the slashes inside a checkId literal so the url reads as the check", () => {
    expect(findingGroupHref("prowler", "gcp/bigquery_dataset_cmk_encryption"))
      .toBe("/findings/prowler/gcp/bigquery_dataset_cmk_encryption");
  });

  it("escapes characters that would otherwise break out of the path", () => {
    expect(findingGroupHref("nuclei", "http/misconfig?a=1#b"))
      .toBe("/findings/nuclei/http/misconfig%3Fa%3D1%23b");
  });

  it("round-trips a checkId through the href it builds", () => {
    const checkId = "gcp/bigquery_dataset_cmk_encryption";
    const tail = findingGroupHref("prowler", checkId).replace("/findings/prowler/", "");
    expect(parseCheckId(tail)).toBe(checkId);
  });

  it("round-trips a checkId carrying reserved characters", () => {
    const checkId = "http/misconfig?a=1#b";
    const tail = findingGroupHref("nuclei", checkId).replace("/findings/nuclei/", "");
    expect(parseCheckId(tail)).toBe(checkId);
  });
});
