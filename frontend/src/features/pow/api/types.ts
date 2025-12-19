// frontend/src/features/pow/api/types.ts

export type PowChallenge = {
  id: string;
  challengeB64: string; // bytes を base64 で
  difficultyBits: number; // 先頭ゼロbit数（UI表示の「難易度N」に対応）
  expiresAtMs: number;
};

export type PowSubmit = {
  challengeId: string;
  nonceU32: number;
  totalHashes: number;
  elapsedMs: number;
};
