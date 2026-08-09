import type { Finding } from "./scans-io.ts";

const OUTPUT_TAIL_CHARS = 20_000;
const LOG_LINE_CHARS = 300;

export type ScanPhase = "idle" | "running" | "done" | "failed" | "cancelled";
export type ScanOutputStream = "stdout" | "stderr" | "system";

export type ScanOutputEvent = {
  sequence: number;
  timestamp: string;
  stream: ScanOutputStream;
  text: string;
};

export type ScanStats = {
  requests: number;
  total: number;
  percent: number;
  rps: number;
  matched: number;
  errors: number;
  hosts: number;
  templates: number;
  duration: string;
};

export type ScanStatus = {
  phase: ScanPhase;
  profile: string | null;
  group: string | null;
  hosts: string[];
  file: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  stats: ScanStats | null;
  findings: Finding[];
  log: string;
  error: string | null;
  command: string[] | null;
  exitCode: number | null;
  observations: number | null;
  output: ScanOutputEvent[];
};

export type ScanOutputState = {
  stats: ScanStats | null;
  log: string;
  pending: Record<"stdout" | "stderr", string>;
  outputEvents: ScanOutputEvent[];
  nextSequence: number;
};

export function createScanOutputState(): ScanOutputState {
  return {
    stats: null,
    log: "",
    pending: { stdout: "", stderr: "" },
    outputEvents: [],
    nextSequence: 1,
  };
}

function parseStats(line: string): ScanStats | null {
  try {
    const value = JSON.parse(line) as Record<string, string>;
    if (value.total == null || value.requests == null) return null;
    const number = (input: string | undefined) => Number(input ?? 0) || 0;
    return {
      requests: number(value.requests),
      total: number(value.total),
      percent: number(value.percent),
      rps: number(value.rps),
      matched: number(value.matched),
      errors: number(value.errors),
      hosts: number(value.hosts),
      templates: number(value.templates),
      duration: value.duration ?? "",
    };
  } catch {
    return null;
  }
}

function appendLogLine(state: ScanOutputState, line: string): void {
  if (!line.trim() || (line.startsWith("{") && parseStats(line))) return;
  state.log +=
    line.length > LOG_LINE_CHARS
      ? `${line.slice(0, LOG_LINE_CHARS)}…\n`
      : `${line}\n`;
  if (state.log.length > OUTPUT_TAIL_CHARS) {
    state.log = state.log.slice(-OUTPUT_TAIL_CHARS);
  }
}

function parseCompletedLines(
  state: ScanOutputState,
  stream: "stdout" | "stderr",
  chunk: string,
): void {
  const lines = (state.pending[stream] + chunk).split("\n");
  state.pending[stream] = lines.pop() ?? "";
  for (const line of lines) {
    const stats = line.startsWith("{") ? parseStats(line) : null;
    if (stats) state.stats = stats;
    appendLogLine(state, line);
  }
}

function trimOutput(events: ScanOutputEvent[]): void {
  let length = events.reduce((total, event) => total + event.text.length, 0);
  while (length > OUTPUT_TAIL_CHARS && events.length > 0) {
    const overflow = length - OUTPUT_TAIL_CHARS;
    const first = events[0];
    if (first.text.length <= overflow) {
      length -= first.text.length;
      events.shift();
      continue;
    }
    first.text = first.text.slice(overflow);
    length -= overflow;
  }
}

export function appendScanOutput(
  state: ScanOutputState,
  stream: ScanOutputStream,
  text: string,
): void {
  if (!text) return;
  state.outputEvents.push({
    sequence: state.nextSequence++,
    timestamp: new Date().toISOString(),
    stream,
    text,
  });
  trimOutput(state.outputEvents);
  if (stream === "system") {
    for (const line of text.split("\n")) appendLogLine(state, line);
    return;
  }
  parseCompletedLines(state, stream, text);
}

export function flushScanOutput(state: ScanOutputState): void {
  for (const stream of ["stdout", "stderr"] as const) {
    const line = state.pending[stream];
    if (!line) continue;
    const stats = line.startsWith("{") ? parseStats(line) : null;
    if (stats) state.stats = stats;
    appendLogLine(state, line);
    state.pending[stream] = "";
  }
}
