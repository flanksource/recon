import type {
  CredentialMode,
  CuratedTarget,
  TargetCredentials,
  TargetKind,
} from "./types";

export type RunTarget = {
  selector?: string;
  id?: string[];
  host?: string[];
  domain?: string[];
  cidr?: string[];
};

export type EngineConfig = Record<string, unknown>;

export type NewTarget = CuratedTarget & {
  id: string;
  kind: TargetKind;
  host?: string;
  provider?: string;
  credentialMode?: CredentialMode;
  arguments?: Record<string, unknown>;
  credentials?: TargetCredentials;
};
