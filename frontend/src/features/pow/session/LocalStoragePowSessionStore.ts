// frontend/src/features/pow/session/CookiePowSessionStore.ts
//
// Session は HTTP-only cookie で管理されるため、
// Frontend から直接 cookie を読み書きしない。
// 代わりに Backend API を呼び出して状態を確認する。

import { powApi } from "../api/powApi";
import type { PowSessionStatus, PowSessionStore } from "./types";

/**
 * Cookie-based PoW Session Store
 *
 * Session は Backend が HTTP-only cookie で管理。
 * Frontend は API 経由で状態を確認・操作する。
 */
export class CookiePowSessionStore implements PowSessionStore {
  async getStatus(): Promise<PowSessionStatus> {
    try {
      const passed = await powApi.checkStatus();
      return passed ? "ok" : "missing";
    } catch {
      return "missing";
    }
  }

  async setOk(): Promise<void> {
    // Session は Backend が submit 成功時に cookie を設定するため、
    // Frontend からは何もしない
  }

  async clear(): Promise<void> {
    await powApi.logout();
  }
}

// 後方互換性のため、LocalStoragePowSessionStore として export
// 新規コードでは CookiePowSessionStore を使用すること
export { CookiePowSessionStore as LocalStoragePowSessionStore };
