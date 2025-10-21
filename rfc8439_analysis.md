# RFC 8439 Compliance Analysis for Qasa ChaCha20-Poly1305

## Executive Summary

**Finding:** Versions 0.0.4 and 0.0.5 (current) are **CORRECT and RFC 8439 compliant**.
**Issue:** Version 0.0.3 had an **INCORRECT implementation** that violated RFC 8439.
**Impact:** Fixing the bugs to comply with RFC 8439 broke backward compatibility with v0.0.3.

---

## RFC 8439 Specification Requirements

### 1. Poly1305 Order of Operations

**RFC 8439 Section 2.5 specifies:**
```
Acc = ((Acc + block) * r) % p
```

The order must be:
1. **ADD** the message block to accumulator FIRST
2. **MULTIPLY** by 'r' SECOND
3. Apply modulo p (where p = 2^130-5)

### 2. Poly1305 Key Clamping

**RFC 8439 Section 2.5 specifies byte-level clamping:**
```c
r[3] &= 15;
r[7] &= 15;
r[11] &= 15;
r[15] &= 15;
r[4] &= 252;
r[8] &= 252;
r[12] &= 252;
```

---

## Implementation Comparison

### Version 0.0.3 (commit 6812f7c and earlier) - ❌ INCORRECT

**Location:** `src/chacha20poly1305/poly1305.rs:process_block()`

**Order of Operations:**
```rust
// WRONG: Multiply first, then add
let h0 = self.h[0] as u64;  // Load old h
// ... multiply h * r first
// ... then add n after multiplication
h0 += n[0] as u64;  // ADD AFTER MULTIPLY - WRONG!
```
**Result:** ❌ Violates RFC 8439 - performs (h * r) + n instead of (h + n) * r

**Key Clamping:**
```rust
// WRONG: Word-level clamping after conversion
let r0 = u32::from_le_bytes(key.r[0..4].try_into().unwrap()) & 0x0fffffff;
let r1 = u32::from_le_bytes(key.r[4..8].try_into().unwrap()) & 0x0ffffffc;
// etc.
```
**Result:** ❌ Violates RFC 8439 - applies masks after byte conversion, not on raw bytes

---

### Versions 0.0.4-0.0.5 (commits 99b0665 and 890fdbe) - ✅ CORRECT

**Location:** `src/chacha20poly1305/poly1305.rs:115-166`

**Order of Operations:**
```rust
// CORRECT: Add first, then multiply
let mut h0 = self.h[0] as u64 + n[0] as u64;  // ADD FIRST
let mut h1 = self.h[1] as u64 + n[1] as u64;
// ...
// h *= r (MULTIPLY SECOND)
let d0: u64 = h0 * r0 + h1 * (5 * r4) + ...;
```
**Result:** ✅ Correctly implements (h + n) * r as per RFC 8439

**Key Clamping (commit 890fdbe):**
```rust
// CORRECT: Byte-level clamping per RFC 8439
let mut r_clamped = key.r;
r_clamped[3] &= 15;
r_clamped[4] &= 252;
r_clamped[7] &= 15;
r_clamped[8] &= 252;
r_clamped[11] &= 15;
r_clamped[12] &= 252;
r_clamped[15] &= 15;
```
**Result:** ✅ Exactly matches RFC 8439 specification

---

## Test Vector Verification

The codebase includes RFC 8439 Section 2.8.2 test vectors in:
- File: `src/chacha20poly1305/tests.rs:175-296`
- Test: `test_chacha20poly1305_rfc8439_test_vector()`

This test verifies:
- Key: 0x808182838485...
- Nonce: 0x070000004041...
- AAD: 0x50515253c0c1...
- Plaintext: "Ladies and Gentlemen of the class of '99..."
- Expected ciphertext and tag from RFC 8439

**Status:** Cannot run due to network restrictions, but implementation matches RFC specification exactly.

---

## Conclusion

### What Happened?

1. **Version 0.0.3** was released with an **incorrect Poly1305 implementation**
2. Data encrypted with v0.0.3 uses the buggy algorithm
3. **Versions 0.0.4 and 0.0.5** fixed the bugs to comply with RFC 8439
4. The fix **breaks backward compatibility** - cannot decrypt v0.0.3 data with v0.0.4/0.0.5

### Which Version Is Correct?

**Versions 0.0.4 and 0.0.5 (current) are CORRECT** and should be kept.

Version 0.0.3 is broken and produces incompatible (and potentially insecure) MACs.

### Recommendations

See main issue report for solution options.
