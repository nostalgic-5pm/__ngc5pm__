// frontend/src/features/pow/components/PixelScene.tsx

import { useEffect, useMemo, useRef } from "react";

type RGB = { r: number; g: number; b: number };

type AirshipState = {
  x: number; // pixel-space
  y: number; // pixel-space
  vx: number; // px / sec
  bornAt: number; // ms
  seed: number;
};

const CANVAS_W = 120;
const CANVAS_H = 70;
const CYCLE_SEC = 30;

// 出現頻度（平均45秒に1回）
const AIRSHIP_MEAN_MS = 45_000;

// 4x4 Bayer
const BAYER_4: number[][] = [
  [0, 8, 2, 10],
  [12, 4, 14, 6],
  [3, 11, 1, 9],
  [15, 7, 13, 5],
];

function clamp01(v: number): number {
  return Math.max(0, Math.min(1, v));
}
function lerp(a: number, b: number, t: number): number {
  return a + (b - a) * t;
}
function mixRGB(a: RGB, b: RGB, t: number): RGB {
  return {
    r: Math.round(lerp(a.r, b.r, t)),
    g: Math.round(lerp(a.g, b.g, t)),
    b: Math.round(lerp(a.b, b.b, t)),
  };
}
function smoothstep(edge0: number, edge1: number, x: number): number {
  const t = clamp01((x - edge0) / (edge1 - edge0));
  return t * t * (3 - 2 * t);
}
function bayer(x: number, y: number): number {
  return BAYER_4[y & 3][x & 3] / 16;
}
function rgb(r: number, g: number, b: number): RGB {
  return { r, g, b };
}

// 2D hash -> 0..1
function hash2(ix: number, iy: number, seed: number): number {
  const x = ix | 0;
  const y = iy | 0;
  let h = (x * 374761393 + y * 668265263 + seed * 1442695041) | 0;
  h = (h ^ (h >>> 13)) | 0;
  h = Math.imul(h, 1274126177);
  h = (h ^ (h >>> 16)) | 0;
  return (h >>> 0) / 4294967295 || 0;
}

// value noise
function valueNoise(x: number, y: number, seed: number): number {
  const xi = Math.floor(x);
  const yi = Math.floor(y);
  const xf = x - xi;
  const yf = y - yi;

  const v00 = hash2(xi, yi, seed);
  const v10 = hash2(xi + 1, yi, seed);
  const v01 = hash2(xi, yi + 1, seed);
  const v11 = hash2(xi + 1, yi + 1, seed);

  const u = xf * xf * (3 - 2 * xf);
  const v = yf * yf * (3 - 2 * yf);

  const a = lerp(v00, v10, u);
  const b = lerp(v01, v11, u);
  return lerp(a, b, v);
}

function expRand(meanMs: number, u01: number): number {
  const u = Math.max(1e-9, Math.min(1 - 1e-9, u01));
  return -Math.log(u) * meanMs;
}

function isReduceMotion(): boolean {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches ?? false;
}

const DISSOLVE_SOFTNESS = 0.18;
const DISSOLVE_BIAS = 0.0;

function dissolveMix(x: number, y: number, segI: number, segT: number, seed: number): number {
  const xNorm = x / (CANVAS_W - 1);

  const rnd = hash2(x, y, seed + 1000 + segI * 1337);
  const ord = bayer(x, y);
  let mask = rnd * 0.75 + ord * 0.25;

  mask = clamp01(mask + (0.5 - xNorm) * DISSOLVE_BIAS);
  return smoothstep(mask - DISSOLVE_SOFTNESS, mask + DISSOLVE_SOFTNESS, segT);
}

type SkyPalette = {
  top: RGB;
  mid: RGB;
  haze: RGB;
  ground: RGB;
};

const PALETTES: SkyPalette[] = [
  {
    top: rgb(145, 110, 255),
    mid: rgb(255, 170, 230),
    haze: rgb(255, 220, 250),
    ground: rgb(165, 245, 220),
  },
  {
    top: rgb(90, 235, 255),
    mid: rgb(235, 255, 255),
    haze: rgb(255, 255, 255),
    ground: rgb(160, 255, 210),
  },
  {
    top: rgb(255, 125, 215),
    mid: rgb(255, 210, 140),
    haze: rgb(255, 235, 205),
    ground: rgb(185, 250, 215),
  },
  {
    top: rgb(18, 10, 58),
    mid: rgb(55, 22, 118),
    haze: rgb(110, 55, 170),
    ground: rgb(70, 110, 135),
  },
  {
    top: rgb(40, 25, 95),
    mid: rgb(120, 70, 195),
    haze: rgb(200, 145, 240),
    ground: rgb(120, 205, 190),
  },
  {
    top: rgb(145, 110, 255),
    mid: rgb(255, 170, 230),
    haze: rgb(255, 220, 250),
    ground: rgb(165, 245, 220),
  },
];

const SEG: number[] = [0.0, 0.22, 0.56, 0.72, 0.92, 1.0];

function findSegment(phase01: number): { i: number; t: number } {
  for (let i = 0; i < SEG.length - 1; i++) {
    if (phase01 >= SEG[i] && phase01 < SEG[i + 1]) {
      const t = (phase01 - SEG[i]) / (SEG[i + 1] - SEG[i]);
      return { i, t };
    }
  }
  return { i: SEG.length - 2, t: 1 };
}

const AIRSHIP_PIXELS: string[] = [
  "        OOOOOOOOO       ",
  "     OBBBBBBBBBBBBBO    ",
  "   OBBBBBBBBBBBBBBBBBO  ",
  "  OBBBBBHHHHHHHHBBBBBBO ",
  " OBBBBBBBBWWWWBBBBBBBBBO",
  " OBBBBBBBBBBBBBBBBBBBBBO",
  "  OBBBBBBBBBBBBBBBBBBBO ",
  "   OOBBBBBBBBBBBBBBBOO  ",
  "      OOOO  OOOO        ",
  "        OGGGGGGGO       ",
  "        GGWWWGGG        ",
  "         OGGGGO         ",
].map((s) => s.slice(0, 24));

const AIRSHIP_W = 24;
const AIRSHIP_H = AIRSHIP_PIXELS.length;

function drawAirship(
  put: (x: number, y: number, c: RGB) => void,
  x0: number,
  y0: number,
  _phase01: number
) {
  // 時間帯に関係なく固定色を使用（ピンク変色を防止）
  const outline = rgb(20, 26, 36);
  const body = rgb(210, 220, 232);
  const hi = rgb(252, 252, 255);
  const gondola = rgb(95, 100, 112);
  const windowC = rgb(250, 250, 250);

  for (let y = 0; y < AIRSHIP_H; y++) {
    const row = AIRSHIP_PIXELS[y];
    for (let x = 0; x < AIRSHIP_W; x++) {
      const ch = row[x] ?? " ";
      if (ch === " ") continue;

      const px = x0 + x;
      const py = y0 + y;

      let c = body;
      if (ch === "O") c = outline;
      else if (ch === "H") c = hi;
      else if (ch === "G") c = gondola;
      else if (ch === "W") c = windowC;

      put(px, py, c);
    }
  }
}

export default function PixelScene() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const startRef = useRef<number>(0);
  const lastDrawRef = useRef<number>(0);
  const lastTickRef = useRef<number>(0);

  const airshipRef = useRef<AirshipState | null>(null);
  const nextSpawnRef = useRef<number>(0);

  const seed = useMemo(() => 0x51a7_2c9d, []);

  const stars = useMemo(() => {
    const pts: Array<{ x: number; y: number; s: number }> = [];
    for (let i = 0; i < 44; i++) {
      const u = hash2(i, i * 7 + 3, seed + 101);
      const v = hash2(i * 11 + 5, i, seed + 202);
      const x = Math.floor(u * CANVAS_W);
      const y = Math.floor(v * Math.floor(CANVAS_H * 0.55));
      const s = 0.7 + hash2(i * 13, i * 17, seed + 303) * 0.6;
      pts.push({ x, y, s });
    }
    return pts;
  }, [seed]);

  useEffect(() => {
    const cv = canvasRef.current;
    if (!cv) return;

    const reduce = isReduceMotion();

    cv.width = CANVAS_W;
    cv.height = CANVAS_H;

    const ctx = cv.getContext("2d", { alpha: false });
    if (!ctx) return;

    const img = ctx.createImageData(CANVAS_W, CANVAS_H);
    const buf = img.data;

    const horizonY = Math.floor(CANVAS_H * 0.56);

    const put = (x: number, y: number, c: RGB) => {
      if (x < 0 || y < 0 || x >= CANVAS_W || y >= CANVAS_H) return;
      const i = (y * CANVAS_W + x) * 4;
      buf[i + 0] = c.r;
      buf[i + 1] = c.g;
      buf[i + 2] = c.b;
      buf[i + 3] = 255;
    };

    const fill = (x: number, y: number, c: RGB) => {
      const i = (y * CANVAS_W + x) * 4;
      buf[i + 0] = c.r;
      buf[i + 1] = c.g;
      buf[i + 2] = c.b;
      buf[i + 3] = 255;
    };

    const drawOnce = (nowMs: number) => {
      if (!startRef.current) startRef.current = nowMs;
      const tSec = (nowMs - startRef.current) / 1000;
      const phase01 = ((tSec % CYCLE_SEC) / CYCLE_SEC + 1) % 1;

      const { i: segI, t: rawT } = findSegment(phase01);
      const segT = smoothstep(0, 1, rawT);

      const palA = PALETTES[segI];
      const palB = PALETTES[segI + 1];

      const nightness =
        smoothstep(SEG[3] - 0.06, SEG[3] + 0.05, phase01) *
        (1 - smoothstep(SEG[4] + 0.02, SEG[4] + 0.07, phase01));
      const dayness = 1 - nightness;

      for (let y = 0; y < CANVAS_H; y++) {
        for (let x = 0; x < CANVAS_W; x++) {
          const m = dissolveMix(x, y, segI, segT, seed);

          if (y >= horizonY) {
            const g = mixRGB(palA.ground, palB.ground, m);
            const n = valueNoise(x / 8, (y + tSec * 1.6) / 10, seed + 33);
            const grain = (n - 0.5) * 9;
            const d = (bayer(x, y) - 0.5) * 6;
            fill(x, y, {
              r: Math.max(0, Math.min(255, g.r + grain + d)),
              g: Math.max(0, Math.min(255, g.g + grain + d)),
              b: Math.max(0, Math.min(255, g.b + grain + d)),
            });
            continue;
          }

          const vy = y / Math.max(1, horizonY);
          const skyA = mixRGB(palA.top, palA.mid, smoothstep(0.0, 0.72, vy));
          const skyB = mixRGB(palB.top, palB.mid, smoothstep(0.0, 0.72, vy));

          const hazeA = mixRGB(skyA, palA.haze, smoothstep(0.65, 1.0, vy));
          const hazeB = mixRGB(skyB, palB.haze, smoothstep(0.65, 1.0, vy));

          let c = mixRGB(hazeA, hazeB, m);

          const dith = (bayer(x, y) - 0.5) * 9;
          c = {
            r: Math.max(0, Math.min(255, c.r + dith)),
            g: Math.max(0, Math.min(255, c.g + dith)),
            b: Math.max(0, Math.min(255, c.b + dith)),
          };

          fill(x, y, c);
        }
      }

      if (nightness > 0.01) {
        for (let i = 0; i < stars.length; i++) {
          const st = stars[i];
          const flick = 0.65 + 0.35 * Math.sin(tSec * (1.35 + st.s) + i * 2.3);
          const a = nightness * flick;
          if (a < 0.12) continue;

          const lum = 170 + Math.floor(70 * a);
          put(st.x, st.y, rgb(lum, lum - 10, lum + 20));

          if (i % 9 === 0 && a > 0.55) {
            put(st.x + 1, st.y, rgb(lum - 40, lum - 30, lum + 10));
          }
        }
      }

      if (dayness > 0.03) {
        const sunX = Math.floor(CANVAS_W * 0.18);
        const sunY = Math.floor(CANVAS_H * 0.2);

        const sigma = 11;
        for (let y = 0; y < horizonY; y++) {
          for (let x = 0; x < CANVAS_W; x++) {
            const dx = x - sunX;
            const dy = y - sunY;
            const d2 = dx * dx + dy * dy;

            const glow = Math.exp(-d2 / (2 * sigma * sigma)) * 0.82 * dayness;
            if (glow < 0.02) continue;

            const i = (y * CANVAS_W + x) * 4;
            const add = 105 * glow;
            const addW = 85 * glow;

            buf[i + 0] = Math.min(255, buf[i + 0] + addW);
            buf[i + 1] = Math.min(255, buf[i + 1] + add);
            buf[i + 2] = Math.min(255, buf[i + 2] + addW);
          }
        }
      }

      // 4) 飛行船：出現制御のみ（出現後は画面外まで生かす）
      const spawnAllowed = phase01 >= SEG[1] && phase01 < SEG[3];
      const now = nowMs;

      if (!airshipRef.current) {
        if (!nextSpawnRef.current) {
          const u = hash2(1, 2, seed + 777);
          nextSpawnRef.current = now + expRand(AIRSHIP_MEAN_MS, u);
        }

        if (spawnAllowed && now >= nextSpawnRef.current) {
          const u1 = hash2(Math.floor(now / 1000), 7, seed + 901);
          const u2 = hash2(3, Math.floor(now / 1000), seed + 902);

          airshipRef.current = {
            x: CANVAS_W + AIRSHIP_W + 2,
            y: Math.floor(8 + u1 * 10),
            vx: 9 + u2 * 6,
            bornAt: now,
            seed: Math.floor(u1 * 1e9) ^ seed,
          };

          const u3 = hash2(Math.floor(now / 1000), 99, seed + 903);
          nextSpawnRef.current = now + expRand(AIRSHIP_MEAN_MS, u3);
        }
      }

      const lastTick = lastTickRef.current || nowMs;
      const dtSec = Math.min(0.05, Math.max(0.0, (nowMs - lastTick) / 1000));
      lastTickRef.current = nowMs;

      if (airshipRef.current) {
        const a = airshipRef.current;
        const ageSec = (now - a.bornAt) / 1000;

        const bob = Math.sin(ageSec * 2.1 + (a.seed % 1000)) * 0.6;

        a.x -= a.vx * dtSec;

        const x0 = Math.round(a.x);
        const y0 = Math.round(a.y + bob);

        drawAirship(put, x0, y0, phase01);

        if (a.x < -AIRSHIP_W - 4) airshipRef.current = null;
      }

      // 5) 雲
      const wind = tSec * 6;
      const cloudStrength = 0.32 * dayness + 0.18 * nightness;

      if (cloudStrength > 0.01) {
        for (let y = 0; y < horizonY; y++) {
          for (let x = 0; x < CANVAS_W; x++) {
            const ny = y / horizonY;
            const hBias = smoothstep(0.05, 0.55, 1 - ny);

            const n = valueNoise((x + wind) / 12, y / 10, seed + 55);
            const n2 = valueNoise((x + wind * 0.6) / 28, y / 18, seed + 56);
            const v = n * 0.7 + n2 * 0.3;

            const th = 0.56;
            const a = clamp01((v - th) / 0.26) * cloudStrength * hBias;
            if (a < 0.06) continue;

            const i = (y * CANVAS_W + x) * 4;
            const cloudCol = mixRGB(rgb(245, 255, 255), rgb(120, 70, 180), nightness);
            const t = a * (0.55 + 0.25 * (bayer(x, y) - 0.5));

            buf[i + 0] = Math.min(255, Math.round(lerp(buf[i + 0], cloudCol.r, t)));
            buf[i + 1] = Math.min(255, Math.round(lerp(buf[i + 1], cloudCol.g, t)));
            buf[i + 2] = Math.min(255, Math.round(lerp(buf[i + 2], cloudCol.b, t)));
          }
        }
      }

      ctx.putImageData(img, 0, 0);
    };

    let raf = 0;
    const loop = (nowMs: number) => {
      const last = lastDrawRef.current || 0;
      if (nowMs - last >= 33) {
        lastDrawRef.current = nowMs;
        drawOnce(nowMs);
      }
      raf = window.requestAnimationFrame(loop);
    };

    if (reduce) {
      drawOnce(performance.now());
      return;
    }

    raf = window.requestAnimationFrame(loop);
    return () => window.cancelAnimationFrame(raf);
  }, [seed, stars]);

  return <canvas ref={canvasRef} className="pixelCanvas" aria-hidden="true" />;
}
