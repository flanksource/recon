import { describe, expect, it } from "vitest";
import {
  appendScanOutput,
  createScanOutputState,
  flushScanOutput,
} from "./scan-runtime.ts";

describe("scan output runtime", () => {
  it("parses split stats without combining interleaved stdout and stderr lines", () => {
    const state = createScanOutputState();

    appendScanOutput(state, "stdout", '{"requests":"5",');
    appendScanOutput(state, "stderr", "retrying ");
    appendScanOutput(
      state,
      "stdout",
      '"total":"10","percent":"50","templates":"3"}\n',
    );
    appendScanOutput(state, "stderr", "request\n");
    flushScanOutput(state);

    expect(state.stats).toMatchObject({ requests: 5, total: 10, percent: 50, templates: 3 });
    expect(state.log).toBe("retrying request\n");
    expect(state.outputEvents).toEqual([
      expect.objectContaining({ sequence: 1, stream: "stdout", text: '{"requests":"5",' }),
      expect.objectContaining({ sequence: 2, stream: "stderr", text: "retrying " }),
      expect.objectContaining({
        sequence: 3,
        stream: "stdout",
        text: '"total":"10","percent":"50","templates":"3"}\n',
      }),
      expect.objectContaining({ sequence: 4, stream: "stderr", text: "request\n" }),
    ]);
  });
});
