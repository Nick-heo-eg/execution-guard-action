/**
 * ITokenStore — Interface contract for token storage backends.
 *
 * FROZEN INTERFACE — v1.0
 * Any change to method signatures requires a major version bump.
 * Public and private implementations must satisfy this exact contract.
 * Do NOT add methods without incrementing the interface version.
 *
 * Implementations:
 *   - MemoryTokenStore (src/stores/memory_store.ts) — reference PoC
 *   - Additional backends available in private kernel
 *
 * The store is NOT the execution authority.
 * Storing a token does NOT grant execution.
 * The kernel's 7-step verification chain is the authority.
 */

import type { VerifiedToken } from '../execution_kernel.js';

export interface ITokenStore {
  /** Store a token under its proposal_hash key. */
  store(proposalHash: string, token: VerifiedToken): void;

  /** Retrieve a token. Returns null if not found or expired. */
  retrieve(proposalHash: string): VerifiedToken | null;

  /** Delete a token (e.g. after use or rejection). */
  delete(proposalHash: string): void;

  /** Check if a token exists (non-expired). */
  has(proposalHash: string): boolean;
}
