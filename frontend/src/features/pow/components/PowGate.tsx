// frontend/src/features/pow/components/PowGate.tsx

import React, { useEffect, useMemo, useState } from "react";
import { powApi } from "../api/powApi";
import { usePow } from "../hooks/usePow";
import { PowOverlay, type PowOverlayVm } from "./PowOverlay";

type Props = {
  children: React.ReactNode;
};

function readPowDebugFlags() {
  const sp = new URLSearchParams(window.location.search);
  const force = sp.get("pow") === "force";
  const reset = sp.get("pow") === "reset";
  const mode = sp.get("powmode") === "sim" ? "sim" : "normal";
  return { force, reset, mode } as const;
}

export function PowGate({ children }: Props) {
  const debug = useMemo(() => readPowDebugFlags(), []);
  const [sessionChecked, setSessionChecked] = useState(false);
  const [sessionValid, setSessionValid] = useState(false);

  // Check existing session on mount, handle ?pow=reset
  useEffect(() => {
    (async () => {
      // ?pow=reset: logout and force PoW
      if (debug.reset) {
        await powApi.logout();
        // Remove reset from URL to prevent infinite loop
        const url = new URL(window.location.href);
        url.searchParams.delete("pow");
        window.history.replaceState({}, "", url.toString());
        setSessionValid(false);
        setSessionChecked(true);
        return;
      }

      // ?pow=force: skip session check, always show PoW
      if (debug.force) {
        setSessionValid(false);
        setSessionChecked(true);
        return;
      }

      // Normal: check if session is valid
      const passed = await powApi.checkStatus();
      setSessionValid(passed);
      setSessionChecked(true);
    })();
  }, [debug.force, debug.reset]);

  // Determine whether PoW is required (avoid issuing challenge before session check completes)
  const needsPow = sessionChecked ? !sessionValid || debug.force : false;

  // Run PoW only when needed
  const pow = usePow({
    enabled: needsPow,
    mode: debug.mode,
  });

  // Show nothing until session check completes
  if (!sessionChecked) {
    return null;
  }

  // If session is valid (and not force mode), skip PoW
  const open = needsPow && pow.phase !== "done";

  const vm: PowOverlayVm = {
    phase: pow.phase,
    progressRatio: pow.progressRatio ?? 0,
    difficulty: pow.difficulty ?? null,
    elapsedMs: pow.elapsedMs ?? 0,
    estimatedRemainSec: pow.estimatedRemainSec ?? null,
    hashRate: pow.hashRate ?? 0,
    totalHashes: pow.totalHashes ?? 0,
  };

  return (
    <div className="appRoot">
      <div className={open ? "blurLayer" : ""}>{children}</div>
      <PowOverlay open={open} vm={vm} />
    </div>
  );
}

export default PowGate;
