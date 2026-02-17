/**
 * ExecutionDeniedError — thrown by execution_kernel.ts when
 * any verification step fails before spawn().
 *
 * spawn() is NEVER reached when this error is thrown.
 * error_type provides machine-readable classification for audit logs.
 */

export type ExecutionDeniedErrorType =
  | 'TOKEN_EXPIRED'
  | 'DECISION_NOT_ALLOW'
  | 'TOKEN_REPLAYED'
  | 'PROPOSAL_HASH_MISMATCH'
  | 'POLICY_HASH_MISMATCH'
  | 'ENV_FINGERPRINT_MISMATCH'
  | 'SIGNATURE_INVALID';

export class ExecutionDeniedError extends Error {
  public readonly error_type: ExecutionDeniedErrorType;

  constructor(error_type: ExecutionDeniedErrorType, message: string) {
    super(message);
    this.name = 'ExecutionDeniedError';
    this.error_type = error_type;
  }
}
