import { useCallback, useEffect, useRef, useState } from "react";
import { fetchScanStatus, SCAN_EVENTS_URL } from "./api";
import type { ScanStatus } from "./types";

// Tracks the server-side scan from its SSE stream. The initial request covers server
// rendering/tests and gives an immediate snapshot while EventSource connects.
export function useScanStatus(onFinish?: (status: ScanStatus) => void) {
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const wasActive = useRef(false);
  const eventVersion = useRef(0);
  const finish = useRef(onFinish);

  useEffect(() => {
    finish.current = onFinish;
  }, [onFinish]);

  const applyStatus = useCallback((next: ScanStatus) => {
    setStatus(next);
    setError(null);
    const active = next.phase === "queued" || next.phase === "running";
    if (wasActive.current && !active) finish.current?.(next);
    wasActive.current = active;
  }, []);

  const refresh = useCallback(async () => {
    const version = eventVersion.current;
    try {
      const next = await fetchScanStatus();
      if (version === eventVersion.current) applyStatus(next);
      return next;
    } catch (e) {
      setError((e as Error).message);
      return null;
    }
  }, [applyStatus]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (typeof EventSource === "undefined") return;
    const source = new EventSource(SCAN_EVENTS_URL);
    source.onmessage = (event) => {
      try {
        const next = JSON.parse(event.data) as ScanStatus;
        eventVersion.current += 1;
        applyStatus(next);
      } catch (cause) {
        setError(`invalid scan event: ${(cause as Error).message}`);
      }
    };
    source.onerror = () => {
      setError("Live scan stream disconnected; reconnecting…");
    };
    return () => source.close();
  }, [applyStatus]);

  return { status, error, refresh, setStatus: applyStatus };
}
