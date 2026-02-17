/**
 * Canonical JSON stringify — sorted keys, no spaces, arrays preserve order.
 *
 * Used by both canonical_proposal (for hash input) and execution_kernel
 * (for signature verification payload reconstruction).
 *
 * Determinism guarantee: same object always produces same string,
 * regardless of insertion order.
 */

export function canonicalStringify(obj: unknown): string {
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalStringify).join(',') + ']';
  }
  if (obj !== null && typeof obj === 'object') {
    const sorted = Object.keys(obj as Record<string, unknown>)
      .sort()
      .map((k) => {
        const v = (obj as Record<string, unknown>)[k];
        return JSON.stringify(k) + ':' + canonicalStringify(v);
      });
    return '{' + sorted.join(',') + '}';
  }
  return JSON.stringify(obj);
}
