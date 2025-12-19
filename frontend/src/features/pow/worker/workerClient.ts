// frontend/src/features/pow/worker/workerClient.ts

export type PowMode = "normal" | "sim";

export type WorkerProgress = {
  kind: "progress";
  totalHashes: number;
  elapsedMs: number;
  hashRate: number; // hashes/sec
};

export type WorkerFound = {
  kind: "found";
  nonceU32: number;
  totalHashes: number;
  elapsedMs: number;
};

export type WorkerMsg = WorkerProgress | WorkerFound;

export type WorkerStart = {
  challengeB64: string;
  difficultyBits: number;
  mode: PowMode;
  simHashRate?: number; // mode=sim のときだけ使用（任意）
};

export function startPowWorker(input: WorkerStart, onMsg: (m: WorkerMsg) => void) {
  const w = new Worker(new URL("./pow.worker.ts", import.meta.url), { type: "module" });
  w.onmessage = (e: MessageEvent<WorkerMsg>) => onMsg(e.data);
  w.postMessage(input);
  return () => w.terminate();
}
