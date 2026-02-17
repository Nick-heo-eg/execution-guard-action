/**
 * Execution Guard Action — Main Entry Point (v0.3.0)
 *
 * Deny-by-default execution layer for GitHub Actions.
 * Built on Execution Boundary architecture (execution-runtime-core).
 *
 * Core is SEALED. This adapter NEVER modifies core.
 * Core invariant hash: 54add9db6f88f28a81bbfd428d47fa011ad9151b91df672c3c1fa75beac32f04
 *
 * v0.3.0: Authority token layer connected to execution path.
 *   - evaluate() → ALLOW → token issued → kernel verifies → spawn
 *   - STOP: token never issued, spawn never reached
 *   - Replay: blocked by token_registry (in-memory + NDJSON)
 *   - Environment change: blocked by fingerprint binding
 *   - Policy change: blocked by policy_hash binding
 */

import * as core from '@actions/core';
import { initRegistry } from './token_registry.js';
import { runAuthorityPipeline } from './authority_pipeline.js';
import { executeWithAuthority } from './execution_kernel.js';

async function run(): Promise<void> {
  // Initialize token replay registry (loads from .execution_audit/used_tokens.ndjson)
  initRegistry();

  // Read inputs via GitHub Actions environment variables
  const rawCommand = process.env['INPUT_COMMAND'] ?? '';
  const policyPath = process.env['INPUT_POLICY_PATH'] ?? './policy.yaml';
  const failOnHoldStr = process.env['INPUT_FAIL_ON_HOLD'] ?? 'true';
  const failOnHold = failOnHoldStr.toLowerCase() !== 'false';

  if (!rawCommand.trim()) {
    core.setFailed('INPUT_COMMAND is required but was not provided.');
    process.exit(1);
  }

  // Parse command string into command + args
  const parts = rawCommand.trim().split(/\s+/);
  const command = parts[0]!;
  const args = parts.slice(1);

  // Run authority pipeline:
  //   evaluate (sealed core) → if ALLOW: issue token → return VerifiedToken
  const pipelineResult = await runAuthorityPipeline(command, args, policyPath);

  // Always output these three fields
  console.log(`DECISION:      ${pipelineResult.decision}`);
  console.log(`PROPOSAL_HASH: ${pipelineResult.proposal_hash}`);
  console.log(`REASON:        ${pipelineResult.reason}`);

  // Set standard outputs
  core.setOutput('verdict', pipelineResult.decision);
  core.setOutput('proposal_hash', pipelineResult.proposal_hash);
  core.setOutput('reason', pipelineResult.reason);

  // Set token outputs (empty string on STOP — token was never issued)
  core.setOutput('token_id', pipelineResult.token?.token_id ?? '');
  core.setOutput('audit_ref', pipelineResult.token?.audit_ref ?? '');
  core.setOutput('environment_fingerprint', pipelineResult.token?.environment_fingerprint ?? '');

  // --- Verdict branching ---

  if (pipelineResult.decision === 'ALLOW') {
    // Token was issued by pipeline — hand it to the kernel for execution
    // Kernel will re-verify all invariants before calling spawn()
    if (!pipelineResult.token || !pipelineResult.proposal) {
      // Should never happen — ALLOW always includes token+proposal
      core.setFailed('[INVARIANT VIOLATION] ALLOW decision but token missing. STOP.');
      process.exit(1);
    }

    console.log(`\n✅ Execution permitted: ${command} ${args.join(' ')}`);
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

    } catch (kernelErr) {
      const msg = kernelErr instanceof Error ? kernelErr.message : String(kernelErr);
      console.error(`\n❌ KERNEL VERIFICATION FAILED: ${msg}`);
      core.setFailed(`Kernel verification failed: ${msg}`);
      process.exit(1);
    }

  } else if (pipelineResult.decision === 'STOP') {
    console.error('\n❌ EXECUTION BLOCKED (STOP)');
    console.error(`   Command: ${command} ${args.join(' ')}`);
    console.error(`   Policy:  ${policyPath}`);
    console.error(`   Reason:  ${pipelineResult.reason}`);
    core.setFailed(`Execution denied by policy. DECISION: STOP`);
    process.exit(1);

  } else {
    // HOLD — soft gate (future extension)
    if (failOnHold) {
      console.warn('\n⚠️  EXECUTION HELD (HOLD) — fail_on_hold=true');
      core.setFailed(`Execution held by policy. DECISION: HOLD`);
      process.exit(1);
    } else {
      console.warn('\n⚠️  EXECUTION HELD (HOLD) — fail_on_hold=false, continuing');
      core.warning(`Execution held by policy but fail_on_hold=false. DECISION: HOLD`);
      process.exit(0);
    }
  }
}

run().catch((err) => {
  core.setFailed(`Unexpected error: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
