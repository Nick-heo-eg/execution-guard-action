/**
 * OpenClaw Token Store — ITokenStore adapter.
 *
 * Uses ITokenStore interface — storage backend is injected or defaulted.
 * Default: MemoryTokenStore (reference/PoC use).
 * Production: FileTokenStore or SecureTokenStore from private kernel.
 *
 * /tmp path removed. Storage strategy is abstracted behind ITokenStore.
 *
 * Security properties preserved:
 *   - TTL validation on retrieve (expired tokens return null)
 *   - The store is NOT the execution authority
 *   - Kernel 7-step verification is always required after retrieval
 *
 * Use case: Human-in-the-loop approval flow.
 *   1. Human reviews proposal (e.g. Telegram UI).
 *   2. Human approves → issuer calls storeToken().
 *   3. OpenClaw executor calls retrieveToken() before kernel call.
 *   4. Token passes through 7-step kernel verification.
 */

import type { ITokenStore } from '../../interfaces/token_store.js';
import { memoryTokenStore } from '../../stores/memory_store.js';
import type { VerifiedToken } from '../../execution_kernel.js';

/** Active store — injectable for testing or production override. */
let activeStore: ITokenStore = memoryTokenStore;

/** Inject a different store implementation (e.g. for testing or production). */
export function setTokenStore(store: ITokenStore): void {
  activeStore = store;
}

export function storeToken(proposalHash: string, token: VerifiedToken): void {
  activeStore.store(proposalHash, token);
}

export function retrieveToken(proposalHash: string): VerifiedToken | null {
  return activeStore.retrieve(proposalHash);
}

export function deleteToken(proposalHash: string): void {
  activeStore.delete(proposalHash);
}

export function hasStoredToken(proposalHash: string): boolean {
  return activeStore.has(proposalHash);
}
