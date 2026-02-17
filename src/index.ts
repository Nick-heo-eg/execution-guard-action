/**
 * Execution Guard Action - Main Entry Point
 *
 * Deny-by-default execution layer for GitHub Actions.
 * Built on Execution Boundary architecture (execution-runtime-core).
 *
 * Core is SEALED. This adapter NEVER modifies core.
 * Core invariant hash: 54add9db6f88f28a81bbfd428d47fa011ad9151b91df672c3c1fa75beac32f04
 */

import * as core from '@actions/core';
import { spawn } from 'child_process';
import { evaluate } from 'execution-runtime-core/src/core/evaluate.js';

// --- Verdict Types ---
// Core returns: ALLOW | DENY
// Guard maps to: ALLOW | STOP | HOLD
//   DENY  → STOP  (hard block, always exit 1)
//   HOLD is reserved for future policy-level soft gates
type GuardVerdict = 'ALLOW' | 'STOP' | 'HOLD';

function mapCoreVerdict(coreVerdict: 'ALLOW' | 'DENY'): GuardVerdict {
  if (coreVerdict === 'ALLOW') return 'ALLOW';
  return 'STOP';
}

async function run(): Promise<void> {
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
  const command = parts[0];
  const args = parts.slice(1);

  // Evaluate via sealed core engine
  const result = evaluate({
    command,
    args,
    policyPath
  });

  // Map to guard verdict
  const verdict: GuardVerdict = mapCoreVerdict(result.verdict);

  // Required log fields (always output these 3)
  console.log(`DECISION: ${verdict}`);
  console.log(`PROPOSAL_HASH: ${result.proposalHash}`);
  console.log(`REASON: ${result.reason}`);

  // Set GitHub Actions outputs
  core.setOutput('verdict', verdict);
  core.setOutput('proposal_hash', result.proposalHash);
  core.setOutput('reason', result.reason);

  // Verdict branching
  if (verdict === 'ALLOW') {
    console.log(`\n✅ Execution permitted: ${command} ${args.join(' ')}`);
    // Spawn the actual command
    await new Promise<void>((resolve, reject) => {
      const child = spawn(command, args, { stdio: 'inherit', shell: false });
      child.on('close', (code) => {
        const exitCode = code ?? 0;
        if (exitCode !== 0) {
          core.setFailed(`Command exited with code ${exitCode}`);
        }
        process.exit(exitCode);
      });
      child.on('error', (err) => {
        core.setFailed(`Spawn error: ${err.message}`);
        process.exit(1);
      });
    });

  } else if (verdict === 'STOP') {
    console.error('\n❌ EXECUTION BLOCKED (STOP)');
    console.error(`   Command: ${command} ${args.join(' ')}`);
    console.error(`   Policy:  ${policyPath}`);
    core.setFailed(`Execution denied by policy. DECISION: STOP`);
    process.exit(1);

  } else if (verdict === 'HOLD') {
    // HOLD: soft gate — future extension
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
