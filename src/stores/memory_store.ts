/**
 * MemoryTokenStore — In-memory ITokenStore implementation.
 *
 * REFERENCE IMPLEMENTATION ONLY.
 * Tokens survive only for the current process lifetime.
 * Use the private kernel's FileTokenStore or SecureTokenStore for production.
 *
 * Security properties preserved:
 *   - TTL validation on retrieve (expired tokens return null)
 *   - The store is NOT the execution authority
 *   - Kernel 7-step verification is always required after retrieval
 */

import type { ITokenStore } from '../interfaces/token_store.js';
import type { VerifiedToken } from '../execution_kernel.js';

interface TokenRecord {
  stored_at: string;
  token: VerifiedToken;
}

export class MemoryTokenStore implements ITokenStore {
  private readonly _tokens = new Map<string, TokenRecord>();

  store(proposalHash: string, token: VerifiedToken): void {
    this._tokens.set(proposalHash, { stored_at: new Date().toISOString(), token });
  }

  retrieve(proposalHash: string): VerifiedToken | null {
    const record = this._tokens.get(proposalHash);
    if (!record) return null;

    if (new Date() > new Date(record.token.expires_at)) {
      this.delete(proposalHash);
      return null;
    }

    return record.token;
  }

  delete(proposalHash: string): void {
    this._tokens.delete(proposalHash);
  }

  has(proposalHash: string): boolean {
    return this.retrieve(proposalHash) !== null;
  }
}

/** Default singleton instance for reference use. */
export const memoryTokenStore = new MemoryTokenStore();
