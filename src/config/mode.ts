/**
 * Gate Mode — controls front-gate evaluation strictness.
 *
 * STRICT (default):
 *   - evaluate() DENY → immediate STOP, no token issued
 *   - evaluate() ALLOW → ALLOW token issued → kernel verify → spawn
 *   - Any rule miss = execution blocked at the gate
 *
 * PERMISSIVE:
 *   - evaluate() DENY → HOLD token issued (decision='HOLD') → kernel blocks spawn
 *   - evaluate() ALLOW → ALLOW token issued → kernel verify → spawn
 *   - Token is always required. Kernel gate is never bypassed.
 *   - Used when you need soft gates (audit trail without hard block)
 *
 * Invariant: execution_kernel.ts NEVER spawns for decision !== 'ALLOW'.
 * Mode controls issuance; kernel controls execution.
 */

export enum GateMode {
  STRICT = 'STRICT',
  PERMISSIVE = 'PERMISSIVE'
}

/**
 * Parse gate mode from environment variable or string input.
 * Defaults to STRICT on any unknown/missing value.
 */
export function parseModeFromEnv(): GateMode {
  const raw = (process.env['INPUT_GATE_MODE'] ?? process.env['GATE_MODE'] ?? '').toUpperCase();
  if (raw === 'PERMISSIVE') return GateMode.PERMISSIVE;
  return GateMode.STRICT; // Fail-strict: unknown mode = STRICT
}
