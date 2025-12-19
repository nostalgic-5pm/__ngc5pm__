/// frontend/src/features/pow/worker/pow.worker.ts

/// <reference lib="webworker" />

export {}; // TSに「モジュール」として認識させる（型衝突回避）

type StartMsg = {
  challengeB64: string;
  difficultyBits: number;
  mode: "normal" | "sim";
  simHashRate?: number;
};

type WorkerProgress = {
  kind: "progress";
  totalHashes: number;
  elapsedMs: number;
  hashRate: number; // hashes/sec
};

type WorkerFound = {
  kind: "found";
  nonceU32: number;
  totalHashes: number;
  elapsedMs: number;
};

type WorkerMsg = WorkerProgress | WorkerFound;

const ctx: DedicatedWorkerGlobalScope = self as unknown as DedicatedWorkerGlobalScope;

function post(msg: WorkerMsg): void {
  ctx.postMessage(msg);
}

function fromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// ---- minimal SHA-256 ----
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}
function ch(x: number, y: number, z: number): number {
  return (x & y) ^ (~x & z);
}
function maj(x: number, y: number, z: number): number {
  return (x & y) ^ (x & z) ^ (y & z);
}
function s0(x: number): number {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >>> 3);
}
function s1(x: number): number {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >>> 10);
}
function S0(x: number): number {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
function S1(x: number): number {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

function sha256(msg: Uint8Array): Uint8Array {
  const l = msg.length;
  const bitLenHi = Math.floor((l * 8) / 2 ** 32);
  const bitLenLo = (l * 8) >>> 0;

  const padLen = (56 - ((l + 1) % 64) + 64) % 64;
  const total = l + 1 + padLen + 8;
  const m = new Uint8Array(total);
  m.set(msg, 0);
  m[l] = 0x80;

  m[total - 8] = (bitLenHi >>> 24) & 0xff;
  m[total - 7] = (bitLenHi >>> 16) & 0xff;
  m[total - 6] = (bitLenHi >>> 8) & 0xff;
  m[total - 5] = bitLenHi & 0xff;
  m[total - 4] = (bitLenLo >>> 24) & 0xff;
  m[total - 3] = (bitLenLo >>> 16) & 0xff;
  m[total - 2] = (bitLenLo >>> 8) & 0xff;
  m[total - 1] = bitLenLo & 0xff;

  let a = 0x6a09e667,
    b = 0xbb67ae85,
    c = 0x3c6ef372,
    d = 0xa54ff53a;
  let e = 0x510e527f,
    f = 0x9b05688c,
    g = 0x1f83d9ab,
    h = 0x5be0cd19;

  const W = new Uint32Array(64);

  for (let i = 0; i < m.length; i += 64) {
    for (let t = 0; t < 16; t++) {
      const j = i + t * 4;
      W[t] = ((m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3]) >>> 0;
    }
    for (let t = 16; t < 64; t++) {
      W[t] = (s1(W[t - 2]) + W[t - 7] + s0(W[t - 15]) + W[t - 16]) >>> 0;
    }

    let A = a,
      B = b,
      C = c,
      D = d,
      E = e,
      F = f,
      G = g,
      H = h;

    for (let t = 0; t < 64; t++) {
      const T1 = (H + S1(E) + ch(E, F, G) + K[t] + W[t]) >>> 0;
      const T2 = (S0(A) + maj(A, B, C)) >>> 0;
      H = G;
      G = F;
      F = E;
      E = (D + T1) >>> 0;
      D = C;
      C = B;
      B = A;
      A = (T1 + T2) >>> 0;
    }

    a = (a + A) >>> 0;
    b = (b + B) >>> 0;
    c = (c + C) >>> 0;
    d = (d + D) >>> 0;
    e = (e + E) >>> 0;
    f = (f + F) >>> 0;
    g = (g + G) >>> 0;
    h = (h + H) >>> 0;
  }

  const out = new Uint8Array(32);
  const Hs = [a, b, c, d, e, f, g, h];
  for (let i = 0; i < 8; i++) {
    out[i * 4] = (Hs[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (Hs[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (Hs[i] >>> 8) & 0xff;
    out[i * 4 + 3] = Hs[i] & 0xff;
  }
  return out;
}

function hasLeadingZeroBits(hash: Uint8Array, bits: number): boolean {
  const full = Math.floor(bits / 8);
  const rem = bits % 8;

  for (let i = 0; i < full; i++) if (hash[i] !== 0) return false;
  if (rem === 0) return true;

  const mask = 0xff << (8 - rem);
  return (hash[full] & mask) === 0;
}

ctx.addEventListener("message", (e: MessageEvent<StartMsg>) => {
  const { challengeB64, difficultyBits, mode, simHashRate } = e.data;

  // --- sim: 低負荷で“終わらない”進捗だけ生成（画面確認用） ---
  if (mode === "sim") {
    const started = performance.now();
    const rate = Math.max(1, simHashRate ?? 250_000); // hashes/sec
    let total = 0;

    ctx.setInterval(() => {
      const now = performance.now();
      const elapsedMs = Math.max(1, Math.round(now - started));
      total += Math.round(rate * 0.25); // 250ms分を加算

      post({
        kind: "progress",
        totalHashes: total,
        elapsedMs,
        hashRate: rate,
      });
    }, 250);

    return; // found を送らない => 永続表示
  }

  // --- normal: 本物のPoW（見つかったら found を返す） ---
  const challenge = fromB64(challengeB64);

  const started = performance.now();
  let total = 0;
  let nonce = (Math.random() * 0xffffffff) >>> 0;

  let lastReportAt = started;
  let lastTotal = 0;

  while (true) {
    for (let i = 0; i < 50_000; i++) {
      const input = concat(challenge, u32be(nonce));
      const h = sha256(input);
      total++;

      if (hasLeadingZeroBits(h, difficultyBits)) {
        const elapsedMs = Math.max(0, Math.round(performance.now() - started));
        post({ kind: "found", nonceU32: nonce >>> 0, totalHashes: total, elapsedMs });
        return;
      }

      nonce = (nonce + 1) >>> 0;
    }

    const now = performance.now();
    if (now - lastReportAt >= 250) {
      const elapsedMs = Math.max(1, Math.round(now - started));
      const deltaHashes = total - lastTotal;
      const deltaSec = (now - lastReportAt) / 1000;
      const hashRate = deltaSec > 0 ? Math.round(deltaHashes / deltaSec) : 0;

      post({ kind: "progress", totalHashes: total, elapsedMs, hashRate });

      lastReportAt = now;
      lastTotal = total;
    }
  }
});
