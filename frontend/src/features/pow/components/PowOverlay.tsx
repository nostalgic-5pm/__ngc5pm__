// frontend/src/features/pow/components/PowOverlay.tsx

import "../ui/pow.css";
import "../ui/powMetricPaper.css";
import PixelScene from "./PixelScene";

export type PowPhase = "computing" | "submitting" | "done" | "error";

export type PowOverlayVm = {
  phase: PowPhase;
  /** 0..1 */
  progressRatio: number;

  difficulty: number | null;

  elapsedMs: number;
  estimatedRemainSec: number | null;

  hashRate: number;
  totalHashes: number;
};

type Props = {
  open: boolean;
  vm: PowOverlayVm;
};

function clamp01(v: number): number {
  return Math.max(0, Math.min(1, v));
}

function isFiniteNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

function fmtSec(s: number | null | undefined): string {
  if (!isFiniteNumber(s)) return "—";
  return `${Math.max(0, s).toFixed(1)}s`;
}

function fmtMsToSec(ms: number | null | undefined): string {
  if (!isFiniteNumber(ms)) return "—";
  return fmtSec(ms / 1000);
}

function fmtCount(n: number | null | undefined): string {
  if (!isFiniteNumber(n)) return "—";
  return `${new Intl.NumberFormat("ja-JP").format(Math.max(0, Math.floor(n)))} 回`;
}

function fmtHs(h: number | null | undefined): string {
  if (!isFiniteNumber(h)) return "—";
  if (h >= 1_000_000) return `${(h / 1_000_000).toFixed(1)} MH/s`;
  if (h >= 1_000) return `${(h / 1_000).toFixed(1)} kH/s`;
  return `${h.toFixed(0)} H/s`;
}

/** progressbar 左上：英語固定 */
function progressLabelEnglish(phase: PowPhase): string {
  switch (phase) {
    case "computing":
      return "processing...";
    case "submitting":
      return "verifying...";
    case "done":
      return "done";
    case "error":
      return "error";
  }
}

function footerTitleJa(phase: PowPhase): string {
  switch (phase) {
    case "done":
      return "証明完了";
    case "error":
      return "エラー";
    case "submitting":
      return "検証中";
    case "computing":
    default:
      return "証明中";
  }
}

export function PowOverlay({ open, vm }: Props) {
  if (!open) return null;

  const pct = clamp01(vm.progressRatio) * 100;

  // フッターは常設（高さ固定）。完了時だけ数値、他は「計算中…」表示。
  const isDone = vm.phase === "done";
  const totalHashesText = isDone ? fmtCount(vm.totalHashes) : "計算中…";
  const elapsedText = isDone ? fmtMsToSec(vm.elapsedMs) : "計算中…";

  return (
    <div
      className="overlayRoot"
      data-phase={vm.phase}
      role="dialog"
      aria-modal="true"
      aria-label="計算量認証"
    >
      <div className="overlayCard">
        {/* 吊り線 + ピン */}
        <div className="hangerLine left" aria-hidden="true" />
        <div className="hangerLine right" aria-hidden="true" />
        <div className="hangerPin left" aria-hidden="true" />
        <div className="hangerPin right" aria-hidden="true" />

        {/* proof-of-work（左揃え） */}
        <div className="overlayCaption">proof-of-work</div>

        <div className="overlayTitle">計算量認証</div>

        {/* 上側の罫線（このデザインが完璧なので維持） */}
        <div className="overlayRule" />

        <div className="overlaySub">あなたが善良な市民であることを証明してください</div>

        <div className="progressRow">
          {/* 英語固定 */}
          <div className="statusText">{progressLabelEnglish(vm.phase)}</div>

          <div className="progressBarWrap">
            <div className="progressBar" aria-hidden="true">
              <div className="progressFill" style={{ width: `${pct}%` }} />
            </div>
            <div className="qedSquare" aria-hidden="true" />
          </div>
        </div>

        <div className="midRow">
          {/* 左（縦2つ）：難易度 + ハッシュレート */}
          <div className="metricCol">
            <div className="metricBox powMetricPaper">
              <div className="metricLabel">Difficulty</div>
              <div className="metricValue">{vm.difficulty ?? "—"}</div>
            </div>

            <div className="metricBox powMetricPaper">
              <div className="metricLabel">Hash Rate</div>
              <div className="metricValue">{fmtHs(vm.hashRate)}</div>
            </div>
          </div>

          {/* 中央：PixelScene */}
          <div className="illustrationBox">
            <div className="illustFrame" aria-hidden="true">
              <PixelScene />
            </div>
          </div>

          {/* 右（縦2つ）：経過 + 予想残 */}
          <div className="metricCol metricColRight">
            <div className="metricBox powMetricPaper">
              <div className="metricLabel">Elapsed</div>
              <div className="metricValue">{fmtMsToSec(vm.elapsedMs)}</div>
            </div>

            <div className="metricBox powMetricPaper">
              <div className="metricLabel">Est. Remain</div>
              <div className="metricValue">{fmtSec(vm.estimatedRemainSec)}</div>
            </div>
          </div>
        </div>

        {/* 下側の罫線も、上側と同じデザインに統一 */}
        <div className="overlayRule overlayRuleBottom" aria-hidden="true" />

        {/* フッター常設 */}
        <div className="overlayFooter" aria-live="polite">
          <div className="footerTitle">{footerTitleJa(vm.phase)}</div>
          <div className="footerStats">
            <div>総計算回数: {totalHashesText}</div>
            <div>所要時間: {elapsedText}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default PowOverlay;
