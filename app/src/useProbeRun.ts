import { useEffect, useRef, useState } from "react";
import { fetchProbe } from "./api";
import { TERMINAL_PHASES, type ProbeRun } from "./types";

// How often a running sweep is re-read. Fast enough that rows appear as hosts
// answer, slow enough that a sweep of the estate is not one request per host.
const POLL_MS = 1000;

/**
 * Follows one liveness sweep until it finishes.
 *
 * Polls the run rather than subscribing to the task stream: clicky's task SSE
 * writes *named* events, and `EventSource.onmessage` only fires for unnamed
 * ones — the same trap that made the scan runtime hand-roll its own broadcaster.
 * The run is also the durable record, so this keeps answering after clicky has
 * garbage-collected the finished task.
 *
 * `onHosts` is called with the hosts whose results appeared since the last tick,
 * so a caller can refresh exactly those inventory rows.
 */
export function useProbeRun(
  id: string | null,
  onHosts?: (hosts: string[]) => void,
) {
  const [run, setRun] = useState<ProbeRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Held in a ref so a caller can pass an inline closure without restarting the
  // poll on every render.
  const notify = useRef(onHosts);

  useEffect(() => {
    notify.current = onHosts;
  }, [onHosts]);

  useEffect(() => {
    setRun(null);
    setError(null);
    if (!id) return undefined;

    let cancelled = false;
    let inFlight = false;
    let finished = false;
    const seen = new Set<string>();

    const poll = async () => {
      // A sweep of the estate can answer more slowly than the interval fires;
      // without this the requests would stack up behind a slow one.
      if (inFlight || finished) return;
      inFlight = true;
      try {
        const next = await fetchProbe(id);
        if (cancelled) return;
        setRun(next);
        setError(null);

        // Every poll returns the whole run, so a caller that did not track what
        // it had already seen would refresh the same inventory row every tick.
        const fresh: string[] = [];
        for (const result of next.results) {
          if (seen.has(result.host)) continue;
          seen.add(result.host);
          fresh.push(result.host);
        }
        if (fresh.length > 0) notify.current?.(fresh);

        // Nothing about a terminal run will change, so stop asking. The interval
        // keeps firing until the effect is torn down, but does no work and
        // sends nothing.
        finished = TERMINAL_PHASES.includes(next.phase);
      } catch (cause) {
        if (!cancelled) setError((cause as Error).message);
      } finally {
        inFlight = false;
      }
    };

    void poll();
    const timer = setInterval(() => void poll(), POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [id]);

  return { run, error };
}
