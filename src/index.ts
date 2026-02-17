/**
 * Execution Guard Action — Main Entry Point (v0.4.0)
 *
 * 3-layer architecture:
 *   Layer 1: Front Gate (GateMode.STRICT | GateMode.PERMISSIVE)
 *   Layer 2: Authority Token (cryptographic binding, replay, TTL, policy lock)
 *   Layer 3: Execution Kernel (single spawn site, 7-step verify)
 *
 * Core is SEALED. This adapter NEVER modifies evaluate.ts.
 * Core invariant hash: 54add9db6f88f28a81bbfd428d47fa011ad9151b91df672c3c1fa75beac32f04
 */

import * as core from '@actions/core';
import { initRegistry } from './token_registry.js';
import { runAuthorityPipeline } from './authority_pipeline.js';
import { executeWithAuthority } from './execution_kernel.js';
import { parseModeFromEnv } from './config/mode.js';
import { ExecutionDeniedError } from './errors.js';

async function run(): Promise<void> {
  // Initialize token replay registry
  initRegistry();

  const rawCommand = process.env['INPUT_COMMAND'] ?? '';
  const policyPath = process.env['INPUT_POLICY_PATH'] ?? './policy.yaml';
  const failOnHoldStr = process.env['INPUT_FAIL_ON_HOLD'] ?? 'true';
  const failOnHold = failOnHoldStr.toLowerCase() !== 'false';
  const mode = parseModeFromEnv();

  if (!rawCommand.trim()) {
    core.setFailed('INPUT_COMMAND is required but was not provided.');
    process.exit(1);
  }

  const parts = rawCommand.trim().split(/\s+/);
  const command = parts[0]!;
  const args = parts.slice(1);

  // Run authority pipeline (Front Gate + Token Issuance)
  const pipelineResult = await runAuthorityPipeline(command, args, policyPath, mode);

  // Structured log line — one per decision event
  const logEntry = {
    decision: pipelineResult.decision,
    proposal_hash: pipelineResult.proposal_hash,
    token_id: pipelineResult.token?.token_id ?? null,
    policy_hash: pipelineResult.token?.policy_hash ?? null,
    environment_fingerprint: pipelineResult.token?.environment_fingerprint ?? null,
    reason: pipelineResult.reason,
    executed: false,
    gate_mode: mode,
    error_type: null as string | null
  };
  process.stdout.write(JSON.stringify(logEntry) + '\n');

  // Legacy human-readable output
  console.log(`DECISION:      ${pipelineResult.decision}`);
  console.log(`PROPOSAL_HASH: ${pipelineResult.proposal_hash}`);
  console.log(`REASON:        ${pipelineResult.reason}`);

  // GitHub Actions outputs
  core.setOutput('verdict', pipelineResult.decision);
  core.setOutput('proposal_hash', pipelineResult.proposal_hash);
  core.setOutput('reason', pipelineResult.reason);
  core.setOutput('token_id', pipelineResult.token?.token_id ?? '');
  core.setOutput('audit_ref', pipelineResult.token?.audit_ref ?? '');
  core.setOutput('environment_fingerprint', pipelineResult.token?.environment_fingerprint ?? '');
  core.setOutput('gate_mode', mode);

  // --- Verdict branching ---

  if (pipelineResult.decision === 'ALLOW') {
    if (!pipelineResult.token || !pipelineResult.proposal) {
      core.setFailed('[INVARIANT VIOLATION] ALLOW with no token. STOP.');
      process.exit(1);
    }

    console.log(`\n✅ Execution permitted (${mode}): ${command} ${args.join(' ')}`);
    console.log(`   token_id:  ${pipelineResult.token.token_id}`);
    console.log(`   audit_ref: ${pipelineResult.token.audit_ref}`);

    try {
      const kernelResult = await executeWithAuthority(
        command,
        args,
        pipelineResult.proposal,
        pipelineResult.token
      );
      if (kernelResult.exit_code !== 0) {
        core.setFailed(`Command exited with code ${kernelResult.exit_code}`);
      }
      process.exit(kernelResult.exit_code);

    } catch (err) {
      const isDenied = err instanceof ExecutionDeniedError;
      const msg = err instanceof Error ? err.message : String(err);
      const errType = isDenied ? (err as ExecutionDeniedError).error_type : 'UNKNOWN';
      console.error(`\n❌ KERNEL VERIFICATION FAILED [${errType}]: ${msg}`);
      core.setFailed(`Kernel verification failed [${errType}]: ${msg}`);
      process.exit(1);
    }

  } else if (pipelineResult.decision === 'STOP') {
    console.error('\n❌ EXECUTION BLOCKED (STOP)');
    console.error(`   Command:   ${command} ${args.join(' ')}`);
    console.error(`   Policy:    ${policyPath}`);
    console.error(`   Mode:      ${mode}`);
    console.error(`   Reason:    ${pipelineResult.reason}`);
    core.setFailed(`Execution denied by policy. DECISION: STOP`);
    process.exit(1);

  } else {
    // HOLD — PERMISSIVE mode soft gate
    console.warn(`\n⚠️  EXECUTION HELD (HOLD) — gate_mode=${mode}`);
    console.warn(`   Command:   ${command} ${args.join(' ')}`);
    console.warn(`   token_id:  ${pipelineResult.token?.token_id ?? 'none'}`);
    if (failOnHold) {
      core.setFailed(`Execution held by policy. DECISION: HOLD`);
      process.exit(1);
    } else {
      core.warning(`Execution held by policy, fail_on_hold=false. DECISION: HOLD`);
      process.exit(0);
    }
  }
}

run().catch((err) => {
  core.setFailed(`Unexpected error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
