#!/usr/bin/env bash
# CI Guard: Enforce single spawn() call site
#
# SECURITY CONTRACT: spawn() / execFile() / exec() MUST only appear
# in src/execution_kernel.ts. Any other call site bypasses the authority
# token verification chain and the 7-step verify protocol.
#
# Exits non-zero if a violation is found.
# Run this in CI on every push (npm run test:guard).

set -euo pipefail

KERNEL_FILE="src/execution_kernel.ts"
KERNEL_PATTERN="execution_kernel"

echo "=== CI Guard: spawn/exec single-site enforcement ==="
echo "    Scope: src/**/*.ts (includes adapters/openclaw/ — no exceptions)"
echo ""

violations=()

# Search all .ts files in src/
while IFS= read -r file; do
  # Skip the authorized kernel file
  if [[ "$file" == *"$KERNEL_PATTERN"* ]]; then
    continue
  fi
  # Skip test files
  if [[ "$file" == *".test."* ]] || [[ "$file" == *".spec."* ]]; then
    continue
  fi

  # Check for child_process import OR direct spawn/exec pattern
  if grep -qE "(from 'child_process'|require\('child_process'\)|child_process\.(spawn|exec|execFile|execFileSync|execSync|spawnSync))" "$file" 2>/dev/null; then
    violations+=("$file")
  fi
done < <(find src -name "*.ts" 2>/dev/null)

if [[ ${#violations[@]} -gt 0 ]]; then
  echo "❌ VIOLATION: child_process found outside execution_kernel.ts"
  echo ""
  echo "   Authorized file: $KERNEL_FILE"
  echo "   Unauthorized files:"
  for v in "${violations[@]}"; do
    echo ""
    echo "     File: $v"
    grep -nE "(from 'child_process'|require\('child_process'\)|child_process\.(spawn|exec|execFile|execFileSync|execSync|spawnSync))" "$v" 2>/dev/null | while IFS= read -r match; do
      echo "       $match"
    done
  done
  echo ""
  echo "   Fix: Remove direct child_process usage. Route through executeWithAuthority()."
  echo "   Authority token verification chain must not be bypassed."
  echo ""
  exit 1
fi

echo "✅ PASS: spawn/exec enforcement — single call site confirmed ($KERNEL_FILE)"
echo ""

# Also verify the kernel file actually contains spawn (sanity check)
if ! grep -q "from 'child_process'" "$KERNEL_FILE" 2>/dev/null; then
  echo "⚠️  WARNING: $KERNEL_FILE does not import child_process. Check if spawn was removed."
fi

exit 0
