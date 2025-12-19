// frontend/src/features/pow/session/types.ts

export type PowSessionStatus = "ok" | "missing";

export interface PowSessionStore {
  getStatus(): Promise<PowSessionStatus>;
  setOk(): Promise<void>;
  clear(): Promise<void>;
}
