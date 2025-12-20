// frontend/src/features/pow/hooks/usePow.ts

import { useEffect, useMemo, useState } from "react";
import { powApi, PowApiError } from "../api/powApi";
import type { PowChallenge } from "../api/types";
import { startPowWorker, type PowMode, type WorkerMsg } from "../worker/workerClient";

export type PowVm = {
  phase: "computing" | "submitting" | "done" | "error";
  statusText: string;
  difficulty: number | null;
  elapsedMs: number;
  totalHashes: number;
  hashRate: number;
  estimatedRemainSec: number | null;

  /** 進捗バー用（0..1） */
  progressRatio: number;

  /** エラーコード（phase=error 時） */
  errorCode?: string;
};

export type UsePowOptions = {
  /** If false, do not issue a challenge and do not start worker */
  enabled?: boolean;
  mode?: PowMode;
  onSuccess?: () => Promise<void> | void;
};

function getPowModeFromUrl(): PowMode {
  const url = new URL(window.location.href);
  const m = url.searchParams.get("powmode");
  if (m === "sim") return "sim";
  return "normal";
}

function getSimHashRateFromUrl(): number | undefined {
  const url = new URL(window.location.href);
  const v = url.searchParams.get("simrate");
  if (!v) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return undefined;
  return Math.floor(n);
}

/** sim時に「満タンまでの目安」を指定（既定は長めに） */
function getSimGoalFromUrl(): number {
  const url = new URL(window.location.href);
  const v = url.searchParams.get("simgoal");
  if (!v) return 10_000_000; // 既定：1000万
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 10_000_000;
  return Math.floor(n);
}

export function usePow(options: UsePowOptions = {}) {
  const enabled = options.enabled ?? true;
  const resolvedMode = useMemo(() => options.mode ?? getPowModeFromUrl(), [options.mode]);
  const onSuccess = options.onSuccess;

  const [challenge, setChallenge] = useState<PowChallenge | null>(null);
  const [vm, setVm] = useState<PowVm>({
    phase: "computing",
    statusText: "processing...",
    difficulty: null,
    elapsedMs: 0,
    totalHashes: 0,
    hashRate: 0,
    estimatedRemainSec: null,
    progressRatio: 0,
  });

  const expectedHashes = useMemo(() => {
    if (vm.difficulty == null) return null;
    // UI上の「期待値」(実際のPoWは確率的。ここは表示用途)
    return Math.pow(2, vm.difficulty);
  }, [vm.difficulty]);

  // If disabled, ensure worker is stopped and state is not "running"
  useEffect(() => {
    if (enabled) return;
    setChallenge(null);
    setVm((p) => ({
      ...p,
      phase: "done",
      statusText: "skipped",
      difficulty: null,
      elapsedMs: 0,
      totalHashes: 0,
      hashRate: 0,
      estimatedRemainSec: null,
      progressRatio: 1,
      errorCode: undefined,
    }));
  }, [enabled]);

  // Issue challenge from Backend (only when enabled)
  useEffect(() => {
    if (!enabled) return;

    let cancelled = false;

    (async () => {
      try {
        const c = await powApi.issue();
        if (cancelled) return;

        setChallenge(c);
        setVm((p) => ({
          ...p,
          difficulty: c.difficultyBits,
          statusText: "processing...",
          phase: "computing",
          elapsedMs: 0,
          totalHashes: 0,
          hashRate: 0,
          estimatedRemainSec: null,
          progressRatio: 0,
          errorCode: undefined,
        }));
      } catch (e) {
        if (cancelled) return;

        const errorCode = e instanceof PowApiError ? e.code : "network";
        setVm((p) => ({
          ...p,
          phase: "error",
          statusText: "error",
          errorCode,
        }));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [enabled]);

  // Run worker when challenge is available
  useEffect(() => {
    if (!challenge) return;

    const simHashRate = getSimHashRateFromUrl();
    const simGoal = getSimGoalFromUrl();

    // 進捗バー/残時間推定に使う「ゴール」
    const goalHashes = resolvedMode === "sim" ? simGoal : (expectedHashes ?? null);

    const stop = startPowWorker(
      {
        challengeB64: challenge.challengeB64,
        difficultyBits: challenge.difficultyBits,
        mode: resolvedMode,
        simHashRate,
      },
      async (m: WorkerMsg) => {
        if (m.kind === "progress") {
          setVm((p) => {
            const goal = goalHashes;
            const ratio = goal && goal > 0 ? Math.min(m.totalHashes / goal, 1) : 0;

            let remain: number | null = p.estimatedRemainSec;
            if (goal && m.hashRate > 0) {
              const r = Math.max(0, goal - m.totalHashes);
              remain = r / m.hashRate;
            } else {
              remain = null;
            }

            return {
              ...p,
              phase: "computing",
              statusText: "processing...",
              elapsedMs: m.elapsedMs,
              totalHashes: m.totalHashes,
              hashRate: m.hashRate,
              estimatedRemainSec: remain,
              progressRatio: ratio,
            };
          });
          return;
        }

        // found（mode=sim では来ない）
        setVm((p) => ({ ...p, phase: "submitting", statusText: "verifying..." }));
        try {
          await powApi.submit({
            challengeId: challenge.id,
            nonceU32: m.nonceU32,
            totalHashes: m.totalHashes,
            elapsedMs: m.elapsedMs,
          });
          setVm((p) => ({
            ...p,
            phase: "done",
            statusText: "done",
            elapsedMs: m.elapsedMs,
            totalHashes: m.totalHashes,
            progressRatio: 1,
          }));
          if (onSuccess) await onSuccess();
        } catch (e) {
          const errorCode = e instanceof PowApiError ? e.code : "network";
          let statusText = "error";

          // エラーコードに応じたメッセージ
          if (e instanceof PowApiError) {
            switch (e.code) {
              case "invalid_nonce":
                statusText = "Invalid solution";
                break;
              case "expired":
                statusText = "Challenge expired";
                break;
              case "rate_limit":
                statusText = "Rate limit exceeded";
                break;
            }
          }

          setVm((p) => ({ ...p, phase: "error", statusText, errorCode }));
        }
      }
    );

    return () => stop();
  }, [challenge, expectedHashes, onSuccess, resolvedMode]);

  return vm;
}
