import type { ScanStatus, TargetRow } from "./types";

export const CONFIRM_CLASSES = new Set(["prod", "public", "unclassified"]);
export const DEFAULT_ENGINE = "nuclei";
export const DEFAULT_PROFILE = "safe";

export type ScanScope = "selected" | "all";

export type ScanDialogProps = {
  open: boolean;
  onClose: () => void;
  rows: TargetRow[];
  savedTargetIds: string[];
  selectedTargetIds: string[];
  status: ScanStatus | null;
  onStatus: (status: ScanStatus) => void;
  onOpenScan?: (id: string) => void;
  allowAllTargets?: boolean;
  discoveryOnly?: boolean;
  editableProfile?: boolean;
  preferredProfile?: string;
};

export function parseProfileRef(ref: string): { engine: string; profile: string } {
  const match = /^scan:([^:]+):([^:]+)$/.exec(ref);
  if (!match) throw new Error(`invalid scan profile reference "${ref}"`);
  return { engine: match[1], profile: match[2] };
}
