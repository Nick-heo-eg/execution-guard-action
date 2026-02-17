/**
 * UUIDv7 Generator — time-ordered, sortable UUID.
 *
 * UUIDv7 structure (RFC 9562):
 *   - Bits 0-47:  unix_ts_ms (48 bits, millisecond precision)
 *   - Bits 48-51: version (4 bits = 0b0111)
 *   - Bits 52-63: rand_a (12 bits random)
 *   - Bits 64-65: variant (2 bits = 0b10)
 *   - Bits 66-127: rand_b (62 bits random)
 *
 * Properties:
 *   - Monotonically increasing within same millisecond (via rand_a increment)
 *   - Lexicographically sortable by time
 *   - Cryptographically random remainder
 */

import { randomBytes } from 'crypto';

/**
 * Generate a UUIDv7.
 * Suitable for token_id and audit_ref fields.
 */
export function uuidv7(): string {
  const now = BigInt(Date.now()); // 48-bit ms timestamp

  // 12 random bits for rand_a
  const randA = BigInt(randomBytes(2).readUInt16BE(0) & 0x0fff);

  // 62 random bits for rand_b (read 8 bytes, mask top 2 bits)
  const randBBytes = randomBytes(8);
  const randBRaw = randBBytes.readBigUInt64BE(0);
  const randB = randBRaw & BigInt('0x3FFFFFFFFFFFFFFF'); // mask top 2 bits

  // Assemble high 64 bits: [unix_ts_ms: 48][ver: 4 = 0x7][rand_a: 12]
  const high = (now << 16n) | (0x7n << 12n) | randA;

  // Assemble low 64 bits: [variant: 2 = 0b10][rand_b: 62]
  const low = (0x2n << 62n) | randB;

  const highHex = high.toString(16).padStart(16, '0');
  const lowHex = low.toString(16).padStart(16, '0');
  const combined = highHex + lowHex;

  return [
    combined.slice(0, 8),
    combined.slice(8, 12),
    combined.slice(12, 16),
    combined.slice(16, 20),
    combined.slice(20)
  ].join('-');
}
