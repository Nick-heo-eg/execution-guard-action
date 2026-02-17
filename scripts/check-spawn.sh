#!/usr/bin/env bash
# CI Guard: Enforce single spawn() call site
#
# SECURITY CONTRACT: spawn() / execFile() / exec() MUST only appear
# in src/execution_kernel.ts. Any other call site bypasses the authority
# token verification chain.
#
# Exits non-zero if a violation is found.
# Run this in CI on every push to main.

set -euo pipefail

KERNEL_FILE="src/execution_kernel.ts"
ALLOWED_PATTERN="execution_kernel"

# Patterns that indicate direct child_process usage
SPAWN_PATTERN="child_process\.(spawn|exec|execFile|execFileSync|execSync|spawnSync)"

# Search all .ts files in src/
violations=()

while IFS= read -r file; do
  # Skip the kernel itself and test files
  if [[ "$file" == *"$ALLOWED_PATTERN"* ]] || [[ "$file" == *".test."* ]] || [[ "$file" == *".spec."* ]]; then
    continue
  fi

  # Check for child_process import or direct spawn/exec calls
  if grep -qE "(from 'child_process'|require\('child_process'\)|$SPAWN_PATTERN)" "$file" 2>/dev/null; then
    violations+=("$file")
  fi
done < <(find src -name "*.ts" 2>/dev/null)

if [[ ${#violations[@]} -gt 0 ]]; then
  echo ""
  echo "❌ [CI GUARD] spawn/exec call site violation detected"
  echo "   Only execution_kernel.ts may import or call child_process spawn/exec."
  echo ""
  echo "   Violations:"
  for v in "${violations[@]}"; do
    echo "     - $v"
    grep -nE "(from 'child_process'|require\('child_process'\)|$SPAWN_PATTERN)" "$v" || true
    echo ""
  done
  echo "   Fix: Remove direct spawn/exec calls. Route through executeWithAuthority()."
  echo ""
  exit 1
fi

echo "✅ [CI GUARD] spawn/exec enforcement passed — single call site confirmed."
exit 0
