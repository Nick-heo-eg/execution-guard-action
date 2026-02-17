/**
 * Token Registry — Reference Implementation
 *
 * REFERENCE ONLY: Demonstrates replay prevention concept.
 * Uses token_id-only replay key (simple in-memory Set).
 *
 * Production kernel: composite key (proposal_hash + environment_fingerprint)
 * — same (proposal, environment) pair executes exactly once per 60s window.
 * See echo-execution-kernel (private).
 *
 * Fail-closed: If registry cannot be read, assume clean state.
 * In-memory only: does not persist across process restarts.
 */

const usedTokenIds = new Set<string>();

/**
 * Initialize registry. No-op for reference implementation
 * (in-memory only — no persistence to load).
 */
export function initRegistry(): void {
  // Reference implementation: memory-only, nothing to load
}

/**
 * Returns true if this token_id has already been used.
 * Reference: token_id-only check.
 * Production kernel: composite key (proposal_hash|env_fp).
 */
export function isTokenUsed(tokenId: string): boolean {
  return usedTokenIds.has(tokenId);
}

/**
 * Mark token as used. In-memory only.
 * Must be called BEFORE command execution.
 */
export function markTokenUsed(
  tokenId: string,
  _auditEntry: Record<string, unknown>
): void {
  usedTokenIds.add(tokenId);
}

/**
 * Append a general audit record. No-op in reference implementation.
 */
export function appendAuditRecord(_entry: Record<string, unknown>): void {
  // Reference implementation: no persistence
}
