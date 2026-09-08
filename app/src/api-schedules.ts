import { json, request } from "./api-client";

export type ScanSchedule = {
  id?: string;
  name: string;
  enabled: boolean;
  engine: string;
  profile: string;
  targets: Record<string, unknown>;
  cron: string;
  timezone: string;
  confirm: boolean;
  nextRun?: string;
  lastRun?: string;
  lastError?: string;
  createdAt?: string;
  updatedAt?: string;
};

/** Includes disabled schedules so they remain editable and can be re-enabled. */
export function fetchSchedules(): Promise<ScanSchedule[]> {
  return request<ScanSchedule[]>("/api/v1/schedule");
}

/** Only configuration is writable; execution timestamps and entity metadata stay on the server. */
export function saveSchedule(
  schedule: ScanSchedule,
  isNew: boolean,
): Promise<ScanSchedule> {
  const { name, enabled, engine, profile, targets, cron, timezone, confirm } =
    schedule;
  return request<ScanSchedule>(
    "/api/v1/schedule",
    json(isNew ? "POST" : "PUT", {
      ...(isNew ? { name } : { id: name }),
      enabled,
      engine,
      profile,
      targets,
      cron,
      timezone,
      confirm,
    }),
  );
}

/** Removes the recurrence without deleting scan history or cancelling an accepted run. */
export function deleteSchedule(name: string): Promise<void> {
  return request<void>(`/api/v1/schedule/${encodeURIComponent(name)}`, {
    method: "DELETE",
  });
}
