/**
 * OpenClaw Proposal — schema, validation, and shell-string rejection.
 *
 * INVARIANT: command MUST be argv[0] only (executable name, no spaces, no shell operators).
 *            args MUST be a pre-split array (not a shell string).
 *
 * Shell strings (pipes, redirections, &&, etc.) are REJECTED here.
 * If OpenClaw generates a complex shell command, it must be decomposed into
 * individual tool proposals or the gate will return STOP with SHELL_STRING_REJECTED.
 */

// Characters that indicate a shell string rather than a bare command/arg
const SHELL_METACHARACTERS = /[|&;<>`$"'()\n\r]/;

export type CommandScope = 'safe' | 'net' | 'fs' | 'admin';

/**
 * Raw proposal from the OpenClaw agent runtime.
 * Validated before any canonical hashing or policy evaluation.
 */
export interface OpenClawProposal {
  source: 'openclaw';
  session_id: string;
  turn_id: string;
  agent_id: string;
  /** argv[0] — executable name only. No shell strings. */
  command: string;
  /** Pre-split argument array. Each element is a single argument. */
  args: string[];
  /** Optional working directory (not used in kernel, for metadata only) */
  cwd?: string;
  /** Explicit allowlist of env vars (for audit metadata) */
  env_allowlist?: string[];
  /** Policy file to use (defaults to ./policy.yaml) */
  policy_ref?: string;
  /** Requested gate mode (caller preference — server enforces its own default) */
  requested_mode?: 'STRICT' | 'PERMISSIVE';
}

export interface ValidationResult {
  valid: true;
  proposal: OpenClawProposal;
}
export interface ValidationFailure {
  valid: false;
  reason: string;
  reason_code: 'SHELL_STRING_REJECTED' | 'VALIDATION_ERROR';
}
export type ValidationOutcome = ValidationResult | ValidationFailure;

/**
 * Validate and sanitize an OpenClaw proposal.
 *
 * Rejects:
 *   - command with whitespace (would indicate shell string)
 *   - command with shell metacharacters
 *   - args that is not an array
 *   - any arg that contains a newline (injection vector)
 *   - malformed/missing required fields
 *
 * Does NOT reject args with spaces — single args may contain spaces (e.g. filenames).
 * DOES reject newlines in args (common injection vector).
 */
export function validateOpenClawProposal(input: unknown): ValidationOutcome {
  if (typeof input !== 'object' || input === null) {
    return { valid: false, reason: 'Proposal must be an object', reason_code: 'VALIDATION_ERROR' };
  }

  const p = input as Record<string, unknown>;

  // source check
  if (p['source'] !== 'openclaw') {
    return { valid: false, reason: `source must be 'openclaw', got: ${p['source']}`, reason_code: 'VALIDATION_ERROR' };
  }

  // required string fields
  for (const field of ['session_id', 'turn_id', 'agent_id', 'command'] as const) {
    if (typeof p[field] !== 'string' || !(p[field] as string).trim()) {
      return { valid: false, reason: `Missing or empty field: ${field}`, reason_code: 'VALIDATION_ERROR' };
    }
  }

  const command = (p['command'] as string).trim();

  // command must be a bare executable — no whitespace
  if (/\s/.test(command)) {
    return {
      valid: false,
      reason: `command contains whitespace — must be argv[0] only, got: "${command}". ` +
              `Shell strings are not accepted. Decompose into separate tool proposals.`,
      reason_code: 'SHELL_STRING_REJECTED'
    };
  }

  // command must not contain shell metacharacters
  if (SHELL_METACHARACTERS.test(command)) {
    return {
      valid: false,
      reason: `command contains shell metacharacters — rejected: "${command}"`,
      reason_code: 'SHELL_STRING_REJECTED'
    };
  }

  // args must be an array
  if (!Array.isArray(p['args'])) {
    return {
      valid: false,
      reason: `args must be an array of strings, got: ${typeof p['args']}. ` +
              `Do not pass shell strings — split into individual arguments.`,
      reason_code: 'VALIDATION_ERROR'
    };
  }

  // each arg must be a string, no newlines
  for (let i = 0; i < (p['args'] as unknown[]).length; i++) {
    const arg = (p['args'] as unknown[])[i];
    if (typeof arg !== 'string') {
      return { valid: false, reason: `args[${i}] is not a string`, reason_code: 'VALIDATION_ERROR' };
    }
    if (/[\n\r]/.test(arg)) {
      return {
        valid: false,
        reason: `args[${i}] contains newline — potential injection vector`,
        reason_code: 'SHELL_STRING_REJECTED'
      };
    }
  }

  // optional fields type checks
  if (p['cwd'] !== undefined && typeof p['cwd'] !== 'string') {
    return { valid: false, reason: 'cwd must be a string if provided', reason_code: 'VALIDATION_ERROR' };
  }
  if (p['policy_ref'] !== undefined && typeof p['policy_ref'] !== 'string') {
    return { valid: false, reason: 'policy_ref must be a string if provided', reason_code: 'VALIDATION_ERROR' };
  }
  if (p['requested_mode'] !== undefined && !['STRICT', 'PERMISSIVE'].includes(p['requested_mode'] as string)) {
    return { valid: false, reason: `requested_mode must be STRICT or PERMISSIVE`, reason_code: 'VALIDATION_ERROR' };
  }

  return {
    valid: true,
    proposal: {
      source: 'openclaw',
      session_id: p['session_id'] as string,
      turn_id: p['turn_id'] as string,
      agent_id: p['agent_id'] as string,
      command,
      args: [...(p['args'] as string[])],
      cwd: p['cwd'] as string | undefined,
      env_allowlist: p['env_allowlist'] as string[] | undefined,
      policy_ref: p['policy_ref'] as string | undefined,
      requested_mode: p['requested_mode'] as 'STRICT' | 'PERMISSIVE' | undefined
    }
  };
}
