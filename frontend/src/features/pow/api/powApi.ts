// frontend/src/features/pow/api/powApi.ts

import type { PowChallenge, PowSubmit } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "";

/**
 * PoW API - Backend 呼び出し
 *
 * ## Security Model
 * - Challenge の発行・検証は全て Backend が Authority
 * - Client は計算実行と API 呼び出しのみ
 * - Session は HTTP-only cookie で管理（localStorage 未使用）
 */
export const powApi = {
  /**
   * GET /api/pow/challenge
   * サーバから新しい challenge を取得
   */
  async issue(): Promise<PowChallenge> {
    const res = await fetch(`${API_BASE}/api/pow/challenge`, {
      method: "GET",
      credentials: "include", // cookie を送受信
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (res.status === 429) {
      throw new PowApiError("rate_limit", "Rate limit exceeded");
    }

    if (!res.ok) {
      throw new PowApiError("network", `Failed to issue challenge: ${res.status}`);
    }

    const data = await res.json();

    return {
      id: data.powChallengeId,
      challengeB64: data.powChallengeB64,
      difficultyBits: data.powDifficultyBits,
      expiresAtMs: data.powExpiresAtMs,
    };
  },

  /**
   * POST /api/pow/submit
   * nonce を送信して検証
   *
   * @returns void on success (204)
   * @throws PowApiError with code "invalid_nonce" (409), "expired" (410), "rate_limit" (429)
   */
  async submit(payload: PowSubmit): Promise<void> {
    const res = await fetch(`${API_BASE}/api/pow/submit`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        challengeId: payload.challengeId,
        nonceU32: payload.nonceU32,
        // Telemetry only (server does not use for verification)
        elapsedMs: payload.elapsedMs,
        totalHashes: payload.totalHashes,
      }),
    });

    if (res.status === 204) {
      // Success - session cookie has been set
      return;
    }

    if (res.status === 409) {
      throw new PowApiError("invalid_nonce", "Invalid nonce");
    }

    if (res.status === 410) {
      throw new PowApiError("expired", "Challenge expired or already consumed");
    }

    if (res.status === 429) {
      throw new PowApiError("rate_limit", "Rate limit exceeded");
    }

    throw new PowApiError("network", `Submit failed: ${res.status}`);
  },

  /**
   * GET /api/pow/status
   * Session の有効性を確認
   */
  async checkStatus(): Promise<boolean> {
    const res = await fetch(`${API_BASE}/api/pow/status`, {
      method: "GET",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
    });

    if (!res.ok) {
      return false;
    }

    const data = await res.json();
    return data.passed === true;
  },

  /**
   * POST /api/pow/logout
   * Session を破棄（?pow=reset 用）
   */
  async logout(): Promise<void> {
    await fetch(`${API_BASE}/api/pow/logout`, {
      method: "POST",
      credentials: "include",
    });
  },
};

export type PowApiErrorCode = "invalid_nonce" | "expired" | "rate_limit" | "network";

export class PowApiError extends Error {
  public code: PowApiErrorCode;

  constructor(code: PowApiErrorCode, message: string) {
    super(message);
    this.name = "PowApiError";
    this.code = code;
  }
}
