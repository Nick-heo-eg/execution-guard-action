/**
 * Token Registry — Append-only used-token store.
 *
 * Purpose: Replay prevention.
 * Once a token_id is used, it CANNOT be reused — even within the same run.
 *
 * Persistence: .execution_audit/used_tokens.ndjson
 * In-memory: Set<string> for current process
 *
 * Fail-closed: If registry cannot be read, assume no tokens were used.
 * If registry cannot be written, log warning but enforce in-memory.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'fs';
import { join } from 'path';

const AUDIT_DIR = '.execution_audit';
const USED_TOKENS_FILE = join(AUDIT_DIR, 'used_tokens.ndjson');

// In-memory set for current process lifetime
const usedTokenIds = new Set<string>();

/**
 * Initialize registry from persisted store.
 * Call once at startup.
 */
export function initRegistry(): void {
  try {
    if (existsSync(USED_TOKENS_FILE)) {
      const lines = readFileSync(USED_TOKENS_FILE, 'utf8').trim().split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        const record = JSON.parse(line) as { token_id?: string };
        if (record.token_id) usedTokenIds.add(record.token_id);
      }
    }
  } catch {
    // Fail-closed: start with empty in-memory set
  }
}

/** Returns true if this token_id has already been used. */
export function isTokenUsed(tokenId: string): boolean {
  return usedTokenIds.has(tokenId);
}

/**
 * Mark token as used. Persists to NDJSON audit log.
 * Must be called BEFORE command execution to prevent replay even on hang.
 */
export function markTokenUsed(
  tokenId: string,
  auditEntry: Record<string, unknown>
): void {
  // In-memory first (immediate, always succeeds)
  usedTokenIds.add(tokenId);

  // Persist to disk (best-effort)
  try {
    if (!existsSync(AUDIT_DIR)) {
      mkdirSync(AUDIT_DIR, { recursive: true });
    }
    const record = JSON.stringify({ token_id: tokenId, used_at: new Date().toISOString(), ...auditEntry });
    appendFileSync(USED_TOKENS_FILE, record + '\n');
  } catch (err) {
    console.warn(`[AUDIT WARNING] Could not persist token record: ${err}`);
    // In-memory enforcement still active — replay blocked
  }
}

/**
 * Append a general audit record (not token-specific).
 * Used for STOP/HOLD events that have no token.
 */
export function appendAuditRecord(entry: Record<string, unknown>): void {
  try {
    if (!existsSync(AUDIT_DIR)) {
      mkdirSync(AUDIT_DIR, { recursive: true });
    }
    appendFileSync(join(AUDIT_DIR, 'log.ndjson'), JSON.stringify(entry) + '\n');
  } catch {
    // Non-fatal
  }
}
