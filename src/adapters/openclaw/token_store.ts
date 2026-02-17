/**
 * Token Store — File-based storage for human-approved authority tokens.
 *
 * Path: /tmp/openclaw_tokens/<proposal_hash>.json
 *
 * Use case: Human-in-the-loop approval (e.g. Telegram "Approve" button).
 *   1. User reviews proposal in Telegram UI.
 *   2. User approves → issuer generates token → storeToken(proposal_hash, token).
 *   3. OpenClaw executor calls retrieveToken(proposal_hash) before kernel call.
 *   4. Token passes through 7-step kernel verification (including replay prevention).
 *   5. After use, token is deleted from store (kernel marks it used in registry).
 *
 * Security properties:
 *   - TTL validation on retrieve (expired tokens are rejected)
 *   - Token is not the execution authority — the kernel's 7-step chain is.
 *   - Storing a token does NOT grant execution. Kernel must verify the token.
 *   - Store is ephemeral (/tmp) — survives only the current session.
 *
 * NOT for production KMS. This is a local runtime convenience layer.
 */

import { mkdirSync, writeFileSync, readFileSync, unlinkSync, existsSync } from 'fs';
import { join } from 'path';
import type { VerifiedToken } from '../../execution_kernel.js';

const TOKEN_STORE_DIR = '/tmp/openclaw_tokens';

function ensureDir(): void {
  if (!existsSync(TOKEN_STORE_DIR)) {
    mkdirSync(TOKEN_STORE_DIR, { recursive: true, mode: 0o700 });
  }
}

function tokenPath(proposalHash: string): string {
  // Sanitize: proposal_hash is a hex SHA256, safe for filenames
  const safe = proposalHash.replace(/[^a-f0-9]/g, '');
  return join(TOKEN_STORE_DIR, `${safe}.json`);
}

/**
 * Store a human-approved token.
 * Overwrites any existing token for this proposal_hash.
 */
export function storeToken(proposalHash: string, token: VerifiedToken): void {
  ensureDir();
  const record = { stored_at: new Date().toISOString(), token };
  writeFileSync(tokenPath(proposalHash), JSON.stringify(record), { encoding: 'utf8', mode: 0o600 });
}

/**
 * Retrieve a stored token for a proposal_hash.
 * Returns null if not found or already expired.
 * Does NOT delete the token — kernel marks it used (replay-prevention).
 */
export function retrieveToken(proposalHash: string): VerifiedToken | null {
  const path = tokenPath(proposalHash);
  if (!existsSync(path)) return null;

  try {
    const raw = readFileSync(path, 'utf8');
    const record = JSON.parse(raw) as { stored_at: string; token: VerifiedToken };
    const token = record.token;

    // Pre-flight TTL check (kernel will re-verify)
    if (new Date() > new Date(token.expires_at)) {
      // Expired — clean up
      deleteToken(proposalHash);
      return null;
    }

    return token;
  } catch {
    return null;
  }
}

/**
 * Delete a stored token (e.g. after use or rejection).
 */
export function deleteToken(proposalHash: string): void {
  const path = tokenPath(proposalHash);
  try {
    if (existsSync(path)) unlinkSync(path);
  } catch {
    // Best-effort cleanup
  }
}

/**
 * Check if a pre-approved token exists for a given proposal_hash.
 */
export function hasStoredToken(proposalHash: string): boolean {
  return retrieveToken(proposalHash) !== null;
}
